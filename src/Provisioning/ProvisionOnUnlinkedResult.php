<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
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
 * listener of SSO's `ResultUnlinked` (IAM-7.1).
 *
 * While a provisioner is bound it writes, in one transaction retried
 * whole on a concurrency failure: the new identity, which must be an Eloquent
 * model the provisioner just inserted; SSO's scope widening for it; its
 * membership; the link, through SSO's provisioning helper; then the roles its
 * groups map to. A refused link rolls everything back and SSO ends the flow as
 * `unlinked`; anything thrown rolls everything back and propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProvisionOnUnlinkedResult
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction  $transaction
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \SineMacula\Laravel\Iam\Tenancy\ScopeWidenings  $widenings
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper  $helper
     * @param  \SineMacula\Laravel\Iam\Provisioning\GroupSettings  $groups
     * @param  \SineMacula\Laravel\Iam\Provisioning\GroupGrants  $grants
     */
    public function __construct(

        /** The container the application binds its provisioner in. */
        private Container $container,

        /** Runs the provisioning in one transaction on the storage connection. */
        private CrossMemberTransaction $transaction,

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
     * Register the listener, resolved from the current application at each
     * dispatch.
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
     * Provision the unlinked result while a provisioner is bound.
     *
     * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function handle(ResultUnlinked $event): void
    {
        if (!$this->container->bound(Provisioner::class)) {
            return;
        }

        $provisioner = $this->container->make(Provisioner::class);

        try {
            $this->transaction->run(fn () => $this->provision($provisioner, $event));
        } catch (RefusedLink) {
            // The helper wrote nothing, and the identity and membership are
            // rolled back
        }
    }

    /**
     * Write the identity, widening, membership, link and group grants, in that
     * order.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\Provisioner  $provisioner
     * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Provisioning\RefusedLink
     * @throws \LogicException
     */
    private function provision(Provisioner $provisioner, ResultUnlinked $event): void
    {
        $result   = $event->result;
        $context  = $event->context();
        $identity = $provisioner->createIdentity($result);

        if (!$identity instanceof Model || !$identity->wasRecentlyCreated) {
            $message = 'The provisioner answered an identity of [%s] it did not create: provisioning always creates a new identity (IAM-7.1).';

            throw new \LogicException(sprintf($message, $identity::class));
        }

        $this->widenings->widen([$identity], $result->tenantId, new ClientContext($context->ip, $context->userAgent));

        $provisioner->createMembership($identity, $result->tenantId, $result);

        $answer = $this->helper->link($event->grant, $result, $this->identities->reference($identity), new SsoClientContext($context->ip, $context->userAgent));

        if (!$answer->isCreated()) {
            throw new RefusedLink($answer);
        }

        $this->mapGroups($identity, $result);
    }

    /**
     * Grant the roles the group mapping answers, if any.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
}
