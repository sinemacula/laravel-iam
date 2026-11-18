<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Mfa\FactorChangeGateAdapter;
use SineMacula\Laravel\Iam\Mfa\ReauthenticatorAdapter;
use SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFactorChangeGate;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * End-to-end tests of a first factor enrolled by a person who signed in
 * through SSO.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeGateAdapter::class)]
#[CoversClass(ReauthenticatorAdapter::class)]
#[CoversClass(ReauthenticationRedemption::class)]
final class SsoFirstFactorEnrolmentTest extends TestCase
{
    use MigratesSso, RunsSsoFlows, SignsInPeople;

    /**
     * Arrange SSO's flows against the fake provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();
    }

    /**
     * Rows of `[whether MFA's own factor-change gate is bound]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideGates(): iterable
    {
        yield 'this package\'s gate' => [false];

        yield 'MFA\'s own gate' => [true];
    }

    /**
     * A reauthentication at the provider lets an SSO session enrol a factor.
     *
     * @param  bool  $mfasOwnGate
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideGates')]
    public function testAReauthenticationAtTheProviderLetsTheSessionEnrolAFirstFactor(bool $mfasOwnGate): void
    {
        if ($mfasOwnGate) {
            $this->app?->bind(FactorChangeGate::class, ConfiguredFactorChangeGate::class);
        }

        $person  = $this->createPerson();
        $session = $this->signInThroughSso($person);

        $this->actingOnSession($session, self::GUARD);

        self::assertSame(FailureReason::NOT_FRESH, Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::totp($person->email))->reason);
        self::assertSame(0, Factor::query()->count());

        $handoff = $this->handoff(Purpose::REAUTHENTICATE, $person, self::keyOf($session));
        $token   = Iam::reauthentications()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client());

        self::assertInstanceOf(AccessTokenResult::class, $token);
        self::assertFalse($token->isFailed(), (string) $token->reason?->value);

        $this->actingOnSession($session, self::GUARD);

        $start = Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::totp($person->email));

        self::assertTrue($start->hasStarted(), (string) $start->reason?->value);
        self::assertNotNull($start->grant);

        $factor       = Factor::query()->sole();
        $confirmation = Mfa::confirmEnrollment(self::servedCaller(), $start->grant, AuthenticatorApp::code($factor));

        self::assertTrue($confirmation->isConfirmed(), (string) $confirmation->reason?->value);
        self::assertSame(FactorStatus::CONFIRMED, $factor->refresh()->getStatus());
    }

    /**
     * Link and sign the person in through SSO, returning the session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function signInThroughSso(Person $person): EloquentSession&Model
    {
        $this->linkThroughFlow($person);

        $handoff = $this->handoff();
        $answer  = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn(), (string) $answer->reason?->value);

        return $answer->session->record ?? self::fail('The sign-in established no session.');
    }
}
