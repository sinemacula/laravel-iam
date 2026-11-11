<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Sso\ReauthenticationSessionsAdapter;
use SineMacula\Laravel\Iam\Sso\RenewalRecorder;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Stands in for the package's reauthentication sessions adapter, answering as
 * it does, except where a test scripts one of the ways an adapter could break
 * the one-renewal rule: recording no renewal, recording one for another
 * session, or recording one while answering the session as not signed in, so
 * SSO refuses the redemption with a renewal still recorded.
 *
 * It counts every renewal SSO asks for, so a test tells how often it was asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedReauthenticationSessions implements ReauthenticationSessions
{
    /** @var string Renew as the package's adapter does. */
    public const string AS_THE_ADAPTER = 'as-the-adapter';

    /** @var string Record no renewal. */
    public const string RECORD_NOTHING = 'record-nothing';

    /** @var string Record the renewal for another session. */
    public const string RECORD_ANOTHER_SESSION = 'record-another-session';

    /** @var string Record a renewal while answering the session as not signed in. */
    public const string RECORD_AND_REFUSE = 'record-and-refuse';

    /** @var int How many renewals SSO asked for. */
    public int $renewals = 0;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $script
     */
    public function __construct(

        /** Resolves the package's adapter and this request's recorder. */
        private readonly Container $container,

        /** How the renewal is scripted. */
        private readonly string $script = self::AS_THE_ADAPTER,
    ) {}

    /**
     * Answer as the package's adapter does.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     */
    #[\Override]
    public function standing(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection): SessionStanding
    {
        return $this->adapter()->standing($identity, $sessionId, $application, $connection);
    }

    /**
     * Answer as the package's adapter does, unless the script records a renewal
     * and answers not signed in.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  string  $linkId
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     */
    #[\Override]
    public function lockedStanding(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection, string $linkId): SessionStanding
    {
        if ($this->script !== self::RECORD_AND_REFUSE) {
            return $this->adapter()->lockedStanding($identity, $sessionId, $application, $connection, $linkId);
        }

        $this->container->make(RenewalRecorder::class)->record($identity, $sessionId, CarbonImmutable::now(), null);

        return SessionStanding::NOT_SIGNED_IN;
    }

    /**
     * Record the renewal as the script says.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     * @return void
     */
    #[\Override]
    public function renewAuthentication(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void
    {
        $this->renewals++;

        match ($this->script) {
            self::RECORD_NOTHING         => null,
            self::RECORD_ANOTHER_SESSION => $this->container->make(RenewalRecorder::class)->record($identity, $sessionId . '-another', $authenticatedAt, $evidence),
            default                      => $this->adapter()->renewAuthentication($identity, $sessionId, $authenticatedAt, $evidence),
        };
    }

    /**
     * The package's adapter.
     *
     * @return \SineMacula\Laravel\Iam\Sso\ReauthenticationSessionsAdapter
     */
    private function adapter(): ReauthenticationSessionsAdapter
    {
        return $this->container->make(ReauthenticationSessionsAdapter::class);
    }
}
