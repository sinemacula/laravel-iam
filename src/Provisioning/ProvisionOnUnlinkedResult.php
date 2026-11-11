<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use Illuminate\Container\Container;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Tenancy\ScopeWidenings;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Http\ClientContext as SsoClientContext;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Provisions a new identity for a `sign_in` result SSO found unlinked: the one
 * listener of SSO's `Events\ResultUnlinked` (IAM-7.1, AUTH-3.9, SSO-8.6).
 *
 * SSO dispatches the event synchronously, with no transaction of its own open
 * and before any handoff, once for a completion, with a grant that allows one
 * use during the dispatch. While a provisioner is configured
 * (`ProvisioningSettings`), asked at each dispatch, so one the application
 * binds after this package registers counts too, this listener writes, in one
 * transaction on the storage connection (`CrossMemberTransaction`), in this
 * order:
 *
 * 1. the new identity (`Provisioner::createIdentity()`), which must be the very
 *    Eloquent model instance that call inserted, its `created` event witnessed
 *    while it ran (`InsertionWitness`), or the listener refuses it with a
 *    `LogicException`: always a new identity, never one found by an attribute
 *    nor one inserted before the call and kept, since the grant proves the
 *    authority to provision for this result and not that the
 *    identity is new;
 * 2. SSO's scope widening for it, first among the writes that give a person a
 *    principal (`ScopeWidenings::widen()`), which takes the new identity's
 *    guard, the first of SSO's locks, and finds nothing to suspend;
 * 3. its membership of the connection's tenant
 *    (`Provisioner::createMembership()`);
 * 4. the link, through SSO's provisioning helper (`ProvisioningHelper::link()`)
 *    with the event's grant, the exact result the event carries, the identity's
 *    reference and the completion's client, which takes the enforcing tenant's
 *    rule, the connection, the request and the links, in SSO's lock order, as a
 *    savepoint of this transaction;
 * 5. once the link is created, while a group mapping is configured
 *    (`GroupSettings`, IAM-7.2), the roles it answers for the groups the result
 *    reports, granted to the new identity in the connection's tenant through
 *    `laravel-authorization` (`GroupGrants::grant()`), after every one of SSO's
 *    locks, so `laravel-authorization`'s come last; a grant that widens the
 *    identity's scope reports it to SSO again through the grant hook, which
 *    finds the identity's guard already held and nothing to suspend.
 *
 * The transaction commits only when the helper answers `created`; a refusal, a
 * value that wrote nothing, rolls the identity and its membership back with it,
 * and the listener returns, so SSO's final step finds the result still unlinked
 * and ends the flow as `unlinked`. Anything thrown (by the provisioner, the
 * widening, the helper, the mapping, a grant or the database) rolls all of it
 * back and propagates, ending the completion as a server error, as SSO's offer
 * does with a listener's exception. The transaction is attempted once, never
 * retried: the helper claims the grant before anything else, in memory, so a
 * second attempt could only be refused `grant_invalid`; a serialisation failure
 * propagates and the person starts a new flow. So that a link committed in the
 * connection while it runs, another person's or the same subject's, never fails
 * it to serialise on PostgreSQL, and so that the widening's locking read of the
 * new identity's links takes no gap lock that would deadlock it against another
 * first sign-in, a link or a reservation on MySQL and MariaDB, the attempt it
 * opens reads committed rows on all three, whatever the storage connection's
 * level (`CommittedReads`), and the helper's locked re-reads see that link.
 * Either way the transaction is committed or rolled back before the listener
 * returns, as SSO requires. Once it commits, the identity, its membership and
 * the link stay made even if the completion's final step then refuses: the next
 * sign-in through the connection resolves through the link.
 *
 * It answers only from the event: the result is `$event->result`, the grant
 * `$event->grant`, and the client the event's context's IP address and user
 * agent, the completion's own; it reads no request, nor the current user. It is
 * registered on SSO's event alone, never on `laravel-authentication`'s
 * informational `ExternalResultUnlinked`, which would provision twice, and is
 * never queued: the event refuses to be serialised, and its grant is void once
 * the dispatch returns. It is resolved from the application current at each
 * dispatch, so under Octane its collaborators are the request's sandbox's.
 * Stateless (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProvisionOnUnlinkedResult
{
    /** @var int How many times the provisioning transaction is attempted: once, since the grant allows one use. */
    private const int ATTEMPTS = 1;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Provisioning\ProvisioningSettings  $settings
     * @param  \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction  $transaction
     * @param  \SineMacula\Laravel\Iam\Provisioning\CommittedReads  $reads
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \SineMacula\Laravel\Iam\Tenancy\ScopeWidenings  $widenings
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper  $helper
     * @param  \SineMacula\Laravel\Iam\Provisioning\GroupSettings  $groups
     * @param  \SineMacula\Laravel\Iam\Provisioning\GroupGrants  $grants
     */
    public function __construct(

        /** Whether provisioning is on, and the application's provisioner. */
        private ProvisioningSettings $settings,

        /** Runs the provisioning in one transaction on the storage connection. */
        private CrossMemberTransaction $transaction,

        /** Has the one attempt read committed rows on PostgreSQL, MySQL and MariaDB. */
        private CommittedReads $reads,

        /** Names the new identity as SSO names an identity. */
        private IdentityReferences $identities,

        /** Reports the new identity's principal to SSO first. */
        private ScopeWidenings $widenings,

        /** Links the result to the new identity, once, with the event's grant. */
        private ProvisioningHelper $helper,

        /** Finds the application's group mapping, if any. */
        private GroupSettings $groups,

        /** Grants the roles the groups map to. */
        private GroupGrants $grants,
    ) {}

    /**
     * Register the listener on SSO's unlinked result, from this package's
     * `boot()`, whatever any switch says: whether a provisioner is configured
     * is asked at each dispatch. The listener is resolved from the application
     * current at the dispatch, never from the events dispatcher's container,
     * which under Octane is the worker's own application while the request's
     * records are its sandbox's. It runs synchronously, as SSO requires.
     *
     * @return void
     */
    public static function listen(): void
    {
        Event::listen(ResultUnlinked::class, static function (ResultUnlinked $event): void {

            Container::getInstance()->make(self::class)->handle($event);
        });
    }

    /**
     * Provision a new identity, its membership and its link for the unlinked
     * result, while a provisioner is configured, in a transaction set to read
     * committed rows before it begins where the engine takes the level then.
     *
     * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\ProvisionerMisconfiguredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function handle(ResultUnlinked $event): void
    {
        $provisioner = $this->settings->provisioner();

        if ($provisioner === null) {
            return;
        }

        $this->reads->beforeBeginning();

        try {
            $this->transaction->run(fn () => $this->provision($provisioner, $event), self::ATTEMPTS);
        } catch (RefusedLink) {
            // The helper wrote nothing, and the identity and membership are
            // rolled back
        }
    }

    /**
     * Write the new identity, report its principal, write its membership, link
     * it and grant what its groups map to, in that order, inside the listener's
     * transaction, once it is set to read committed rows where the engine takes
     * the level once begun, and refuse the transaction when the helper refuses
     * the link.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\Provisioner  $provisioner
     * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Provisioning\RefusedLink
     */
    private function provision(Provisioner $provisioner, ResultUnlinked $event): void
    {
        $this->reads->onceBegun();

        $result   = $event->result;
        $context  = $event->context();
        $identity = self::created(...InsertionWitness::witness(static fn (): Identity => $provisioner->createIdentity($result)));

        $this->widenings->widen([$identity], $result->tenantId, new ClientContext($context->ip, $context->userAgent));

        $provisioner->createMembership($identity, $result->tenantId, $result);

        $answer = $this->helper->link($event->grant, $result, $this->identities->reference($identity), new SsoClientContext($context->ip, $context->userAgent));

        if (!$answer->isCreated()) {
            throw new RefusedLink($answer);
        }

        $this->mapGroups($identity, $result);
    }

    /**
     * Grant the new identity the roles the configured group mapping answers for
     * the result's groups, in the connection's tenant; with no mapping, grant
     * nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException
     * @throws \Throwable
     */
    private function mapGroups(Identity $identity, #[\SensitiveParameter] VerifiedResult $result): void
    {
        $mapping = $this->groups->mapping();

        if ($mapping === null) {
            return;
        }

        $this->grants->grant($identity, $result->tenantId, $mapping->grantsFor($result->connectionId, $result->tenantId, GroupGrants::groupsOf($result)));
    }

    /**
     * The identity the provisioner answered, refused unless it is the very
     * Eloquent model instance its call inserted.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  bool  $inserted
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     */
    private static function created(Identity $identity, bool $inserted): Identity
    {
        if (!$inserted) {
            $message = 'The provisioner answered an identity of [%s] it did not create: provisioning always creates a new identity (IAM-7.1).';

            throw new \LogicException(sprintf($message, $identity::class));
        }

        return $identity;
    }
}
