<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * SSO's reauthentication sessions, answered from `laravel-authentication`'s
 * external standing, with the renewal recorded for the redemption to write.
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
     * Whether the identity is signed in on the session, locking nothing.
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
     * Whether the identity is signed in through the link, locking the row.
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
     * Record the renewal for the redemption to write.
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
     * Refuse a locked standing outside a transaction, where no row is held.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertIsInTransaction(): void
    {
        if (StorageConnection::isInTransaction()) {
            return;
        }

        throw new \LogicException('A session\'s locked standing is asked inside the redemption\'s transaction on the storage connection, which holds its row.');
    }
}
