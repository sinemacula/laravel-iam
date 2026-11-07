<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Sso\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;

/**
 * Reports that a person comes to hold a principal, first, inside the
 * transaction that gives it to them (IAM-7.3): a membership created or
 * accepted, of a tenant, or a platform principal created (`null` tenant).
 *
 * The check SSO makes when a reservation by a verified domain is made and again
 * when it is activated cannot see a principal added and removed between them,
 * so the change itself reports it, through SSO's scope widening
 * (`Linking\ScopeWidening::widened()`): SSO takes the identity's guard and
 * holds it to the commit, suspends the identity's links by a verified domain in
 * every connection of another tenant, deletes its reservations there, and
 * revokes the sessions established through each such link in that same
 * transaction, through the session revocation this package binds
 * (`linkScopeWidened()`, never the switchable `linkRemoved()`). A second report
 * of the same principal suspends and revokes nothing more.
 *
 * Call it before the principal is written, before the application takes its own
 * guard of the person's principals, inside the transaction on the storage
 * connection that writes it (`Iam::transaction()` opens one); then write the
 * principal and commit. Called with no transaction open there, it is SSO's
 * `LogicException`, with nothing locked or written: a suspension that commits
 * apart from the change, or a report made after it, leaves a window in which a
 * reservation or an activation sees the old principals. Inside the caller's
 * transaction it runs once, in a savepoint of it (`CrossMemberTransaction`)
 * rolled back whenever it fails, so a caller that catches the failure keeps
 * none of its suspensions, and its failure reaches the caller in a form the
 * caller's own retry recognises: SSO's `LinkCandidatesChanged` and a
 * serialisation failure are retried only as the caller's whole transaction.
 *
 * The identity is handed over as a plain value and named to SSO by its morph
 * class and key (`IdentityReferences::reference()`), an identity that is no
 * Eloquent model throwing `UnresolvedReferenceException` (IAM-8.2); the client
 * the change is made for is `laravel-authentication`'s client context, which
 * every `LinkSuspended` carries (`new ClientContext(null, null)` from a console
 * command or a job). It reads no request, nor the current user. SSO's scope
 * widening is resolved on each call. Stateless (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class ScopeWidenings
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\Iam\Storage\StorageConnection  $storage
     * @param  \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction  $transaction
     */
    public function __construct(

        /** Resolves SSO's scope widening on each call. */
        private Container $container,

        /** Names the identity as SSO names an identity. */
        private IdentityReferences $identities,

        /** The connections the change runs on. */
        private DatabaseManager $database,

        /** The storage connection's name. */
        private StorageConnection $storage,

        /** Runs the report in a savepoint of the caller's transaction. */
        private CrossMemberTransaction $transaction,
    ) {}

    /**
     * Report that the identity comes to hold a principal in the tenant, or a
     * platform principal (`null`), for the client, inside the caller's
     * transaction on the storage connection; answer how many of the identity's
     * links by a verified domain this suspended.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $tenantId
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return int
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function widen(Identity $identity, ?string $tenantId, ClientContext $client): int
    {
        $reference = $this->identities->reference($identity);
        $widening  = $this->container->make(ScopeWidening::class);
        $sso       = ClientTranslator::toSso($client);

        if ($this->database->connection($this->storage->name())->transactionLevel() === 0) {
            return $widening->widened($reference, $tenantId, $sso);
        }

        return $this->transaction->run(static fn (): int => $widening->widened($reference, $tenantId, $sso));
    }
}
