<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind as AuthenticationProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\StepUpAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\StepUpTests;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for MFA's step-up over `laravel-authentication`'s
 * (IAM-3.4): a verified proof bound to the caller's current session for
 * `step_up` steps that session up, and a failed result, a proof bound to
 * another identity or another of its sessions, and a proof
 * `laravel-authentication` refuses are refused with a reason; an application
 * that is no guard, and a guard holding no session of the identity, throw
 * (IAM-8.2). A refusal inside MFA's transaction rolls back what the transaction
 * wrote, a step-up rolls back with the transaction it ran in, and the only lock
 * it takes is the session's, last.
 *
 * The sessions are real ones, signed in through `laravel-authentication` with a
 * password, and the adapter is resolved on its own, so none of this package's
 * other adapters takes part.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StepUpAdapter::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class StepUpAdapterTest extends TestCase
{
    use MigratesMembers, RunsAtIsolationLevels, SignsInPeople, StepUpTests;

    /** @var string The reference of the factor the step-up proves. */
    private const string FACTOR = 'factor-1';

    /** @var string What the tests roll their own transaction back with. */
    private const string ROLLED_BACK = 'The transaction rolls back.';

    /** @var string The detail of a refusal of a proof bound to another identity or session than the caller's. */
    private const string NOT_BOUND = 'The proof is not bound to the caller\'s current session.';

    /**
     * A verified proof bound to the caller's current session for `step_up`
     * steps the session up: the session records it, and the access token result
     * issued for the session is the completion.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheProofStepsTheCallersSessionUp(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $token = $this->adapter()->stepUp($this->verifiedResult($person, $this->signInReference($session)));

        self::assertTrue($token->isIssued());
        self::assertNotNull($token->accessToken);
        self::assertSame($session->getSessionIdentifier(), $token->session?->getSessionIdentifier());

        $proof = $this->proofsOf($session)[0];

        self::assertSame(AuthenticationProofKind::ADDITIONAL_FACTOR, $proof->kind);
        self::assertSame(AuthenticationPurpose::STEP_UP, $proof->purpose);
        self::assertSame('totp', $proof->method);
        self::assertSame(self::FACTOR, $proof->factor);
        self::assertSame(AuthenticationChannelKind::AUTHENTICATOR_APP, $proof->channel->kind);
        self::assertTrue($proof->evaluation?->multifactor);
        self::assertCount(2, $this->proofsOf($session));
    }

    /**
     * Rows of `[refreshes multifactor, multifactor of the whole session]`.
     *
     * @return iterable<string, array{0: bool, 1: bool}>
     */
    public static function provideMultifactorEvidence(): iterable
    {
        yield 'refreshes it, the whole session multifactor' => [true, true];
        yield 'refreshes it, the whole session not multifactor' => [true, false];
        yield 'does not refresh it, the whole session multifactor' => [false, true];
        yield 'does not refresh it, the whole session not multifactor' => [false, false];
    }

    /**
     * The proof is recorded accepted, at the time MFA proved it, and
     * multifactor exactly when MFA says it refreshes the multifactor evidence
     * of the session's first factor, whatever MFA's evaluation of the whole
     * session says.
     *
     * @param  bool  $refreshes
     * @param  bool  $wholeSession
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMultifactorEvidence')]
    public function testTheProofIsRecordedMultifactorOnlyWhenItRefreshesTheEvidence(bool $refreshes, bool $wholeSession): void
    {
        $signedIn = CarbonImmutable::now()->startOfSecond();

        CarbonImmutable::setTestNow($signedIn);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        CarbonImmutable::setTestNow($signedIn->addMinute());

        $result = $this->verifiedResult($person, $this->signInReference($session), refreshes: $refreshes, wholeSession: $wholeSession, provedAt: $signedIn->addSeconds(30));

        self::assertTrue($this->adapter()->stepUp($result)->isIssued());

        $proof = $this->proofsOf($session)[0];

        self::assertTrue($proof->evaluation?->accepted);
        self::assertSame($refreshes, $proof->evaluation->multifactor);
        self::assertTrue($result->proof?->provedAt->equalTo($proof->authenticatedAt));
    }

    /**
     * A proof bound to another identity, on the caller's current session, is
     * refused, and nothing is recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofOfAnotherIdentityIsRefused(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $refusal = self::assertNotAccepted(fn (): mixed => $this->adapter()->stepUp($this->verifiedResult($this->createPerson(), $this->signInReference($session))));

        self::assertSame(self::NOT_BOUND, $refusal->getMessage());
        self::assertCount(1, $this->proofsOf($session));
    }

    /**
     * A proof bound to another of the identity's live sessions than the guard's
     * is refused, and neither session records it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofOfAnotherOfTheIdentitysSessionsIsRefused(): void
    {
        $person  = $this->createPerson();
        $other   = $this->signIn($person)->record;
        $session = $this->signInAndActOnSession($person);

        $refusal = self::assertNotAccepted(fn (): mixed => $this->adapter()->stepUp($this->verifiedResult($person, $this->signInReference($other))));

        self::assertSame(self::NOT_BOUND, $refusal->getMessage());
        self::assertCount(1, $this->proofsOf($other));
        self::assertCount(1, $this->proofsOf($session));
    }

    /**
     * A proof `laravel-authentication` will not take for a step-up, one made
     * for a sign-in, is refused with its reason in the detail, and nothing is
     * recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofLaravelAuthenticationRefusesIsRefused(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $refusal = self::assertNotAccepted(fn (): mixed => $this->adapter()->stepUp($this->verifiedResult($person, $this->signInReference($session), Purpose::SIGN_IN)));

        self::assertSame('laravel-authentication refused the step-up: [proof_invalid].', $refusal->getMessage());
        self::assertCount(1, $this->proofsOf($session));
    }

    /**
     * A session revoked since the request was authenticated, which the guard
     * still holds, is not stepped up: `laravel-authentication` refuses it under
     * the session's lock, and nothing is recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionNoLongerLiveIsNotSteppedUp(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        self::revoke($session);

        $refusal = self::assertNotAccepted(fn (): mixed => $this->adapter()->stepUp($this->verifiedResult($person, $this->signInReference($session))));

        self::assertSame('laravel-authentication refused the step-up: [session_revoked].', $refusal->getMessage());
        self::assertSame([], $this->proofsOf($session));
    }

    /**
     * Rows of `[application]` that name no guard of `laravel-authentication`'s:
     * one that is no guard at all, and Laravel's own session guard.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideApplicationsThatAreNoGuard(): iterable
    {
        yield 'no guard' => ['not-a-guard'];

        yield 'another kind of guard' => ['web'];
    }

    /**
     * A proof bound to an application that is no guard of
     * `laravel-authentication`'s cannot be resolved, and throws.
     *
     * @param  string  $application
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideApplicationsThatAreNoGuard')]
    public function testAnApplicationThatIsNoGuardIsUnresolved(string $application): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $exception = self::assertUnresolved(fn (): mixed => $this->adapter()->stepUp($this->verifiedResult($person, '1', application: $application)), ReferenceKind::GUARD);

        self::assertSame($application, $exception->application);
        self::assertStringStartsWith(sprintf('The application [%s] is not a laravel-authentication guard', $application), $exception->getMessage());
    }

    /**
     * A guard serving no one, and a guard acting as the identity on no session,
     * cannot resolve the session, and throw.
     *
     * @return void
     */
    public function testAGuardWithoutTheIdentitysSessionIsUnresolved(): void
    {
        $person = $this->createPerson();

        $exception = self::assertUnresolved(fn (): mixed => $this->adapter()->stepUp($this->verifiedResult($person, '1')));

        self::assertStringStartsWith('The guard [api] holds no current session', $exception->getMessage());

        $this->actingAsIdentity($person, guard: self::GUARD);

        self::assertUnresolved(fn (): mixed => $this->adapter()->stepUp($this->verifiedResult($person, '1')));
    }

    /**
     * A refusal inside MFA's transaction rolls back what the transaction wrote
     * before it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalRollsBackTheTransactionItIsMadeIn(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        self::assertNotAccepted(fn (): mixed => DB::transaction(function () use ($person, $session): AccessTokenResult {

            VerificationGeneration::advance($person);

            return $this->adapter()->stepUp($this->verifiedResult($person, $this->signInReference($session), Purpose::SIGN_IN));
        }));

        self::assertSame(0, VerificationGeneration::current($person));
        self::assertCount(1, $this->proofsOf($session));
    }

    /**
     * A step-up made inside MFA's transaction rolls back with it, as when the
     * transaction fails after the step-up, its last write.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpRollsBackWithTheTransactionItIsMadeIn(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        try {
            DB::transaction(function () use ($person, $session): void {

                VerificationGeneration::advance($person);

                self::assertTrue($this->adapter()->stepUp($this->verifiedResult($person, $this->signInReference($session)))->isIssued());

                throw new \RuntimeException(self::ROLLED_BACK);
            });
        } catch (\RuntimeException $exception) {
            self::assertSame(self::ROLLED_BACK, $exception->getMessage());
        }

        self::assertSame(0, VerificationGeneration::current($person));
        self::assertCount(1, $this->proofsOf($session));
    }

    /**
     * Inside MFA's transaction, holding the identity's state row, the step-up
     * locks the session's row and takes no lock of MFA's, so it never takes a
     * lock out of the order identity state, factors, challenge, session row.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testTheSessionRowIsTheOnlyLockItTakes(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $locks   = [];

        DB::transaction(function () use ($person, $session, &$locks): void {

            VerificationGeneration::advance($person);

            DB::listen(static function (QueryExecuted $query) use (&$locks): void {

                if (preg_match('/\b(for update|for share|for no key update|lock in share mode)\b/i', $query->sql) !== 1) {
                    return;
                }

                $locks[] = $query->sql;
            });

            self::assertTrue($this->adapter()->stepUp($this->verifiedResult($person, $this->signInReference($session)))->isIssued());
        });

        self::assertNotSame([], array_filter($locks, static fn (string $sql): bool => str_contains($sql, $session->getTable())));
        self::assertSame([], array_filter($locks, static fn (string $sql): bool => str_contains($sql, 'mfa_')));
    }

    /**
     * The step-up under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\StepUp
     */
    #[\Override]
    protected function stepUp(): StepUp
    {
        return $this->adapter();
    }

    /**
     * A successful result bound to another of the identity's live sessions than
     * the one the guard holds.
     *
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function stepUpResultOfAnotherBinding(): VerificationResult
    {
        $person = $this->createPerson();
        $other  = $this->signIn($person)->record;

        $this->signInAndActOnSession($person);

        return $this->verifiedResult($person, $this->signInReference($other));
    }

    /**
     * A verified TOTP proof of the person's, bound to the sign-in on the
     * application for the purpose given, made at the time given (now by
     * default), refreshing the multifactor evidence or not, with MFA's
     * evaluation of the whole session multifactor or not (both by default).
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $signIn
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  bool  $refreshes
     * @param  bool  $wholeSession
     * @param  ?\Carbon\CarbonImmutable  $provedAt
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    private function verifiedResult(
        Person $person,
        string $signIn,
        Purpose $purpose = Purpose::STEP_UP,
        string $application = self::GUARD,
        bool $refreshes = true,
        bool $wholeSession = true,
        ?CarbonImmutable $provedAt = null,
    ): VerificationResult {
        $reference = IdentityReference::of($person);

        $proof = new Proof(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP, self::FACTOR),
            self::FACTOR,
            ObservedProperties::none(),
            $provedAt ?? CarbonImmutable::now(),
            new ProofBinding($reference->type, $reference->key, $application, $signIn, $purpose),
            VerificationGeneration::current($person),
        );

        $evaluation = new Evaluation(
            accepted: true,
            multifactor: $wholeSession,
            level: $wholeSession ? AssuranceLevel::AAL2 : AssuranceLevel::AAL1,
            phishingResistant: false,
            restricted: false,
            amr: $wholeSession ? ['otp', 'mfa'] : ['otp', 'mca'],
            met: [],
            unmet: [],
        );

        return VerificationResult::verified($proof, $evaluation, ['otp', 'mfa'], 'totp', $refreshes);
    }

    /**
     * Mark the session revoked in storage, as another request revoking it
     * would, while this request's guard still holds it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     */
    private static function revoke(EloquentSession&Model $session): void
    {
        $session->newQuery()->whereKey($session->getKey())->update(['revoked_at' => CarbonImmutable::now()->subSecond(), 'revoked_reason' => 'signed_out']);
    }

    /**
     * Assert the call is refused as not accepted, by this package and not by
     * MFA, and return the refusal.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function assertNotAccepted(\Closure $call): OperationRefusedException
    {
        try {
            $call();
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_ACCEPTED, $exception->reason);
            self::assertFalse($exception->byPackage);

            return $exception;
        }

        self::fail('The step-up was not refused.');
    }

    /**
     * Assert the call cannot resolve the session, and return the exception.
     *
     * @param  \Closure(): mixed  $call
     * @param  \SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind  $kind
     * @return \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function assertUnresolved(\Closure $call, ReferenceKind $kind = ReferenceKind::SESSION): UnresolvedReferenceException
    {
        try {
            $call();
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame($kind, $exception->kind);

            return $exception;
        }

        self::fail('The step-up resolved a session.');
    }

    /**
     * Resolve the adapter under test from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\StepUpAdapter
     */
    private function adapter(): StepUpAdapter
    {
        $adapter = $this->app?->make(StepUpAdapter::class);

        self::assertInstanceOf(StepUpAdapter::class, $adapter);

        return $adapter;
    }
}
