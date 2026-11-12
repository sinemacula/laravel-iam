<?php

declare(strict_types = 1);

namespace Tests\Integration\Audit;

use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Audit\AuditRegistrations;
use SineMacula\Laravel\Iam\Audit\Correlation;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthenticationEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\MfaEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\Snapshot;
use SineMacula\Laravel\Iam\Audit\Mappers\SsoEventMapper;
use SineMacula\Laravel\Iam\Exceptions\ExternalSignInRefusedException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Contract tests for the whole record sequence of a password sign-in, an MFA
 * step-up and an SSO sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditRegistrations::class)]
#[CoversClass(AuthenticationEventMapper::class)]
#[CoversClass(MfaEventMapper::class)]
#[CoversClass(SsoEventMapper::class)]
#[CoversClass(Snapshot::class)]
#[WithConfig('audit-log.capture.laravel.except_guards', [self::GUARD])]
#[WithConfig('audit-log.definitions.require_registered', true)]
final class RecordSequencesTest extends TestCase
{
    use ArrangesFactorChanges, MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The guard's own identity type, as the morph map names the fixture. */
    private const string PERSON = Person::class;

    /** @var string A TOTP code no time step accepts. */
    private const string WRONG_CODE = '000000';

    /**
     * A password sign-in is a session written and a person signed in,
     * correlated by the session.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAPasswordSignIn(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $fake    = AuditLog::fake();
        $session = self::keyOf($this->signIn($person)->record);
        $person  = self::keyOf($person);
        $own     = self::own($person, $session, Correlation::session($session));

        self::assertSame([
            ['session.created', ...$own, ['method' => 'password']],
            ['authentication.signed_in', ...$own, null],
        ], self::sequence($fake));
    }

    /**
     * A step-up after a wrong code is a failed verification, the step-up and a
     * passed verification.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnMfaStepUp(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $record  = $this->signInAndActOnSession($person);
        $factor  = $this->confirmedFactor($person);
        $fake    = AuditLog::fake();
        $session = self::keyOf($record);
        $own     = self::own(self::keyOf($person), $session, Correlation::session($session));
        $kept    = ['application' => self::GUARD, 'purpose' => 'step_up', 'factor_id' => $factor->id, 'factor_type' => 'totp', 'type' => 'totp'];

        self::assertFalse(Mfa::verify(self::callerOf($person), Submission::factor($factor->id, self::WRONG_CODE), Purpose::STEP_UP)->isVerified());

        $this->travel(1)->minutes();

        self::assertTrue(Mfa::verify(self::callerOf($person), Submission::factor($factor->id, AuthenticatorApp::code($factor)), Purpose::STEP_UP)->isVerified());

        $failed = $own;

        $failed[0] = 'failure';
        $failed[1] = 'invalid_code';
        $failed[2] = null;

        self::assertSame([
            ['mfa.verification_failed', ...$failed, $kept],
            ['session.stepped_up', ...$own, ['method' => 'totp', 'kind' => 'additional_factor']],
            ['mfa.verification_passed', ...$own, $kept],
        ], self::sequence($fake));
    }

    /**
     * An SSO sign-in is SSO's halves then `laravel-authentication`'s, each
     * recorded once and correlated.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnSsoSignIn(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->arrangeSso();

        $person = $this->createPerson();

        $this->linkThroughFlow($person);

        $fake    = AuditLog::fake();
        $handoff = $this->handoff();
        $answer  = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertNotNull($answer->session);

        $id       = self::keyOf($person);
        $session  = self::keyOf($answer->session->record);
        $signIn   = Correlation::ssoSignIn($this->connectionId, $handoff->reference);
        $sso      = ['connection_id' => $this->connectionId, 'connection_tenant_id' => self::TENANT, 'protocol' => 'oidc', 'application' => self::GUARD, 'purpose' => 'sign_in'];
        $person   = [self::PERSON, $id];
        $tenant   = ['tenant', self::TENANT];
        $verified = ['success', null, $person, $person, null, $tenant, self::GUARD, null, $signIn, [self::CLIENT_IP, self::CLIENT_AGENT]];

        self::assertNotNull($signIn);
        self::assertSame([
            ['sso.authorization_request_started', 'success', null, null, null, null, $tenant, self::GUARD, null, $signIn, [self::CLIENT_IP, self::CLIENT_AGENT], $sso],
            ['sso.result_verified', ...$verified, $sso],
            ['sso.handoff_issued', ...$verified, $sso],
            ['sso.handoff_redeemed', ...$verified, $sso],
            ['session.created', ...self::own($id, $session, Correlation::session($session)), ['method' => 'external_provider']],
            ['authentication.signed_in', ...self::own($id, $session, Correlation::session($session)), null],
            [
                'authentication.external_result_redeemed',
                ...self::own($id, $session, $signIn),
                ['method' => 'external_provider', 'flow' => 'sign_in', 'connection_id' => $this->connectionId],
            ],
        ], self::sequence($fake));
    }

    /**
     * A refused SSO sign-in records SSO's halves, then the refusal once the
     * redemption rolls back.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusedSsoSignIn(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->arrangeSso();

        $person = $this->createPerson();

        $this->linkThroughFlow($person);

        $fake    = AuditLog::fake();
        $handoff = $this->handoff();

        Config::set('auth.guards.' . self::GUARD . '.application.methods', ['password']);

        $this->app?->make('auth')->forgetGuards();

        try {
            Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

            self::fail('The sign-in was not refused.');
        } catch (ExternalSignInRefusedException $refused) {
            self::assertSame('method_not_allowed', $refused->result->reason?->value);
        }

        $signIn   = Correlation::ssoSignIn($this->connectionId, $handoff->reference);
        $sso      = ['connection_id' => $this->connectionId, 'connection_tenant_id' => self::TENANT, 'protocol' => 'oidc', 'application' => self::GUARD, 'purpose' => 'sign_in'];
        $id       = [self::PERSON, self::keyOf($person)];
        $tenant   = ['tenant', self::TENANT];
        $client   = [self::CLIENT_IP, self::CLIENT_AGENT];
        $verified = ['success', null, $id, $id, null, $tenant, self::GUARD, null, $signIn, $client];

        self::assertSame([
            ['sso.authorization_request_started', 'success', null, null, null, null, $tenant, self::GUARD, null, $signIn, $client, $sso],
            ['sso.result_verified', ...$verified, $sso],
            ['sso.handoff_issued', ...$verified, $sso],
            ['authentication.sign_in_failed', 'failure', 'method_not_allowed', null, null, null, null, self::GUARD, null, $signIn, $client, null],
        ], self::sequence($fake));
    }

    /**
     * What a record of the person's own action holds after its code.
     *
     * @param  string  $person
     * @param  string  $session
     * @param  ?string  $correlation
     * @return list<mixed>
     */
    private static function own(string $person, string $session, ?string $correlation): array
    {
        $reference = [self::PERSON, $person];

        return ['success', null, $reference, $reference, $reference, null, self::GUARD, $session, $correlation, [self::CLIENT_IP, self::CLIENT_AGENT]];
    }

    /**
     * Every record the fake store holds, in order, as its columns and
     * properties.
     *
     * @param  \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore  $fake
     * @return list<list<mixed>>
     */
    private static function sequence(FakeAuditStore $fake): array
    {
        return array_map(static fn (AuditRecord $record): array => [
            $record->event,
            $record->outcome,
            $record->reason,
            self::pair($record->actorType, $record->actorId),
            self::pair($record->subjectType, $record->subjectId),
            self::pair($record->principalType, $record->principalId),
            self::pair($record->tenantType, $record->tenantId),
            $record->guard,
            $record->sessionId,
            $record->correlationId,
            [$record->ip, $record->userAgent],
            $record->properties,
        ], $fake->recorded());
    }

    /**
     * A reference's type and id, or `null` for none.
     *
     * @param  ?string  $type
     * @param  ?string  $id
     * @return ?list<string>
     */
    private static function pair(?string $type, ?string $id): ?array
    {
        return $type === null || $id === null ? null : [$type, $id];
    }
}
