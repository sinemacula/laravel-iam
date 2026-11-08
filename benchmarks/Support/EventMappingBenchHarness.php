<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext as AuthenticationContext;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Audit\DeferredRefusals;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthenticationEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\MfaEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\SsoEventMapper;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Sso\Events\EventContext as SsoContext;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;

/**
 * Event mapping benchmark fixtures: a sign-in, a refused sign-in for a
 * concealed reason, an MFA verification passed and an SSO handoff redeemed,
 * each with a full context, built once, and the three mappers.
 *
 * Mapping runs synchronously for every event a member dispatches, inside the
 * dispatching flow and, for an event dispatched at once, inside whatever
 * transaction is open, so its cost is paid on every sign-in, refusal and
 * verification. Each mapping describes the event on a fresh builder, as
 * audit-log's capture hands each mapper one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EventMappingBenchHarness
{
    /** @var string The client's IP address. */
    private const string IP = '192.0.2.10';

    /** @var string The client's user agent. */
    private const string AGENT = 'bench';

    /** @var string The session every event is about. */
    private const string SESSION = '01JB0000000000000000000000';

    /** @var \SineMacula\Laravel\Authentication\Events\SignedIn A person signed in. */
    private SignedIn $signedIn;

    /** @var \SineMacula\Laravel\Authentication\Events\AuthenticationFailed A sign-in refused for a concealed reason. */
    private AuthenticationFailed $refused;

    /** @var \SineMacula\Laravel\Mfa\Events\VerificationPassed A step-up's verification passed. */
    private VerificationPassed $verified;

    /** @var \SineMacula\Laravel\Sso\Events\HandoffRedeemed An SSO sign-in's handoff redeemed. */
    private HandoffRedeemed $redeemed;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $person  = (new Person)->forceFill(['id' => 7]);
        $client  = new ClientContext(self::IP, self::AGENT);
        $context = new AuthenticationContext('api', $client, $person, $person, new ClaimedTenant('tenant-1'), null, 'password', self::SESSION);

        $this->signedIn = new SignedIn($context, false);
        $this->refused  = new AuthenticationFailed($context, AuthenticationFlow::SIGN_IN, FailureReason::ACCOUNT_RATE_LIMITED, 'ada@example.test', 30, 'challenge-1');
        $this->verified = new VerificationPassed([
            'identity_type'  => Person::class,
            'identity_id'    => '7',
            'principal_type' => Person::class,
            'principal_id'   => '7',
            'tenant_id'      => 'tenant-1',
            'application'    => 'api',
            'session_id'     => self::SESSION,
            'ip'             => self::IP,
            'user_agent'     => self::AGENT,
        ], new FactorSummary('01JF0000000000000000000000', 'totp', 'Phone', null, FactorStatus::CONFIRMED, true, null), 'totp', Purpose::STEP_UP, 'challenge-1');
        $this->redeemed = new HandoffRedeemed(new SsoContext(
            CarbonImmutable::now(),
            ip: self::IP,
            userAgent: self::AGENT,
            connectionId: '01JC0000000000000000000000',
            connectionTenantId: 'tenant-1',
            protocol: 'oidc',
            application: 'api',
            purpose: 'sign_in',
            requestReference: 'reference-1',
            identityMorphClass: Person::class,
            identityId: '7',
        ));
    }

    /**
     * Map the sign-in.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function mapsASignIn(): void
    {
        (new AuthenticationEventMapper(new DeferredRefusals))->map($this->signedIn, new PendingRecord);
    }

    /**
     * Map the concealed refusal.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function mapsARefusal(): void
    {
        (new AuthenticationEventMapper(new DeferredRefusals))->map($this->refused, new PendingRecord);
    }

    /**
     * Map the verification.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function mapsAVerification(): void
    {
        (new MfaEventMapper)->map($this->verified, new PendingRecord);
    }

    /**
     * Map the redemption.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function mapsARedemption(): void
    {
        (new SsoEventMapper)->map($this->redeemed, new PendingRecord);
    }
}
