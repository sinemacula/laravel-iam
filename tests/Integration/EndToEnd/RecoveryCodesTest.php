<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Mfa\FactorChangeGateAdapter;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Mfa\Pending\Concerns\ArrangesPendingSessions;
use Tests\TestCase;

/**
 * End-to-end tests of MFA's recovery codes with every adapter bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeGateAdapter::class)]
#[CoversClass(PendingCompletionAdapter::class)]
final class RecoveryCodesTest extends TestCase
{
    use ArrangesFactorChanges, ArrangesPendingSessions;

    /** @var int How long a step-up keeps a session fresh for a factor change, in seconds. */
    private const int FACTOR_CHANGE_SECONDS = 900;

    /**
     * A code generated after a step-up completes one pending sign-in only.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeGeneratedAfterAStepUpCompletesOnePendingSignIn(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $factor  = $this->confirmedFactor($person);

        $this->stepUpThroughMfa($factor);
        $this->travel(self::FACTOR_CHANGE_SECONDS + 1)->seconds();

        $stale = Mfa::generateRecoveryCodes(self::servedCaller());

        self::assertFalse($stale->wasGenerated());
        self::assertSame(FailureReason::NOT_FRESH, $stale->reason);
        self::assertSame(0, Mfa::recoveryCodeStatus(self::servedCaller())?->remaining);

        $this->stepUpThroughMfa($factor);

        $generated = Mfa::generateRecoveryCodes(self::servedCaller());

        self::assertTrue($generated->wasGenerated(), (string) $generated->reason?->value);
        self::assertSame(count($generated->codes), Mfa::recoveryCodeStatus(self::servedCaller())?->remaining);

        $code       = ($generated->codes[0] ?? self::fail('No recovery code was generated.'))->reveal();
        $credential = $this->signInPending($person);
        $result     = Mfa::verify(self::servedCaller(self::requestCarrying($credential)), Submission::recoveryCode($code));
        $completion = $result->completion();

        self::assertTrue($result->isVerified(), (string) $result->reason?->value);
        self::assertInstanceOf(SignInResult::class, $completion);
        self::assertTrue($completion->isSignedIn(), (string) $completion->reason?->value);

        $signedIn = $completion->session->record ?? self::fail('No session was signed in.');

        self::assertNotSame($session->getKey(), $signedIn->getKey());
        self::assertSame(SessionStatus::ACTIVE, Session::query()->whereKey($signedIn->getKey())->sole()->getStatus());
        self::assertSame([ProofKind::RECOVERY_CODE, ProofKind::FIRST_FACTOR], array_map(static fn (RecordedProof $proof): ProofKind => $proof->kind, $this->proofsOf($signedIn)));

        $again  = $this->signInPending($person);
        $reused = Mfa::verify(self::servedCaller(self::requestCarrying($again)), Submission::recoveryCode($code));

        self::assertSame(FailureReason::INVALID_CODE, $reused->reason);
        self::assertNull($reused->completion());
        self::assertSame([], $this->pendingContextFor($again)->proofs);
    }

    /**
     * Enable recovery codes on the application people sign in on.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $app->make('config')->set('mfa.applications.' . self::GUARD . '.recovery_codes', ['enabled' => true]);
    }

    /**
     * Step the acting session up through MFA with the factor's current code.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return void
     *
     * @throws \Throwable
     */
    private function stepUpThroughMfa(Factor $factor): void
    {
        $result = Mfa::verify(self::servedCaller(), Submission::factor($factor->id, AuthenticatorApp::code($factor)), Purpose::STEP_UP);

        self::assertTrue($result->isVerified(), (string) $result->reason?->value);
    }
}
