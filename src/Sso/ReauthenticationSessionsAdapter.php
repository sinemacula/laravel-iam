<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * SSO's reauthentication sessions, answered from `laravel-authentication`'s
 * external standing of a session, with its renewal recorded and never written
 * (IAM-4.2).
 *
 * - `standing()`, as a `reauthenticate` flow starts, outside any transaction:
 *   whether the session is one of the identity's, established through the
 *   connection by any link, live and active, on the guard the application is,
 *   which allows the `external_provider` method, as `laravel-authentication`'s
 *   `externalStanding()` answers it with no link, reading on the write
 *   connection and locking nothing.
 * - `lockedStanding()`, inside the redemption's transaction, after SSO's locks:
 *   the same, through exactly the link given, on the guard the application is,
 *   whose `externalStanding()` locks the session's row until the transaction
 *   ends. `laravel-authentication` compares the session's guard with the
 *   application's itself, so a session of another application, through another
 *   link or through none, is `not_signed_in`. Asked outside a transaction on
 *   the session model's connection, it could lock nothing, so it throws a
 *   `LogicException` rather than answer unprotected.
 * - `renewAuthentication()` writes nothing: it records the renewal
 *   (`RenewalRecorder`), and `ReauthenticationRedemption` makes the one write
 *   through `laravel-authentication`'s `reauthenticateExternally()` once SSO's
 *   admission answers, in the same transaction. A second renewal in one
 *   redemption is a `LogicException`, and so is a renewal asked for while no
 *   redemption is open to write it: a `reauthenticate` code is redeemed through
 *   `Iam::reauthentications()` alone, and one admitted through SSO's own
 *   `HandoffRedemption::admit()` rolls back with its code unspent rather than
 *   commit as redeemed with nothing renewed.
 *
 * Any reason `laravel-authentication` gives (`session_unknown` and
 * `session_guard_mismatch` among them) is `not_signed_in`: it is the answer,
 * never a refusal by throwing. What cannot be resolved throws
 * `UnresolvedReferenceException` (IAM-8.2), rolling the redemption back: an
 * identity reference that names no identity of `laravel-authentication`'s, and
 * an application that is no guard holding sessions.
 *
 * The recorder is resolved from the container on every call, so a renewal is
 * one request's or one job's alone (IAM-8.1); the adapter itself keeps nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReauthenticationSessionsAdapter implements ReauthenticationSessions
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     */
    public function __construct(

        /** Resolves this request's renewal recorder on every call. */
        private Container $container,

        /** Resolves the guards and their session services. */
        private CurrentSession $sessions,

        /** Resolves the identity SSO names. */
        private IdentityReferences $identities,
    ) {}

    /**
     * Whether the identity is signed in on the session, of the application,
     * through the connection, as a flow starts, locking nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function standing(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection): SessionStanding
    {
        $reason = $this->sessions->sessions($application)->externalStanding($sessionId, $this->identities->identity($identity), $connection->getConnectionId());

        return $reason === null ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
    }

    /**
     * Whether the identity is signed in on the session, of the application,
     * through the connection and exactly the link, with the session's row
     * locked until the redemption's transaction ends.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  string  $linkId
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function lockedStanding(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection, string $linkId): SessionStanding
    {
        $this->assertIsInTransaction();

        $sessions = $this->sessions->sessions($application);
        $reason   = $sessions->externalStanding($sessionId, $this->identities->identity($identity), $connection->getConnectionId(), $linkId);

        return $reason === null ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
    }

    /**
     * Record the renewal of the session's authentication, writing nothing: the
     * redemption makes the one write once SSO's admission answers. Asked while
     * no redemption is open to write it, it throws.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    #[\Override]
    public function renewAuthentication(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void
    {
        $this->container->make(RenewalRecorder::class)->record($identity, $sessionId, $authenticatedAt, $evidence);
    }

    /**
     * Refuse a locked standing asked outside a transaction on the session
     * model's connection, where no row could be held.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertIsInTransaction(): void
    {
        if ($this->sessions->isInTransaction()) {
            return;
        }

        throw new \LogicException('A session\'s locked standing is asked inside the redemption\'s transaction on the storage connection, which holds its row.');
    }
}
