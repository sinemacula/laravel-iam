<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\SteppedUp;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind as AuthenticationProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\StepUpAdapter;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\StepUpTests;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Concerns\BindsStrayRequests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RecordsRequirementDecisions;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for MFA's step-up over `laravel-authentication`'s
 * (IAM-3.4): a verified proof bound to one of the caller's sessions for
 * `step_up` steps the session it is bound to up, whatever the guard holds, for
 * the client MFA served the caller, and a failed result, a caller that is
 * pending, nobody or on another application, a proof bound to another identity
 * or to a session that is not the identity's, and a proof
 * `laravel-authentication` refuses are refused with a reason; an application
 * that is no guard throws (IAM-8.2). A refusal inside MFA's transaction rolls
 * back what the transaction wrote, a step-up rolls back with the transaction it
 * ran in, and the only lock it takes is the session's, last.
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
    use BindsStrayRequests, MigratesMembers, RecordsRequirementDecisions, RunsAtIsolationLevels, SignsInPeople, StepUpTests;

    /** @var string The reference of the factor the step-up proves. */
    private const string FACTOR = 'factor-1';

    /** @var string What the tests roll their own transaction back with. */
    private const string ROLLED_BACK = 'The transaction rolls back.';

    /** @var string The detail of a refusal of a proof bound to another identity than the caller. */
    private const string NOT_BOUND = 'The proof is not bound to the caller.';

    /** @var ?\Tests\Fixtures\Models\Person The person the kit's step-ups are for. */
    private ?Person $kitPerson = null;

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

        $token = $this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, $this->signInReference($session)));

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
     * Once the session is stepped up, the decisions `laravel-authorization`
     * keeps for the request are forgotten (IAM-6.11), so the next check reads
     * the step-up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDecisionThatReadTheSessionsAuthenticationIsForgotten(): void
    {
        $person    = $this->createPerson();
        $session   = $this->signInAndActOnSession($person);
        $reference = $this->signInReference($session);

        $this->recordDecision();

        $this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, $reference));

        self::assertNull($this->lastDecision());
    }

    /**
     * A step-up that is refused changes nothing the decision read, so the
     * decision is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedStepUpKeepsTheDecision(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $decision = $this->recordDecision();

        try {
            $this->adapter()->stepUp(self::callerOf($person), VerificationResult::failed(FailureReason::NOT_ACCEPTED, 'The code did not match.'));

            self::fail('A failed verification stepped the session up.');
        } catch (OperationRefusedException) {
            self::assertSame($decision, $this->lastDecision());
        }
    }

    /**
     * The step-up is made for the client MFA served the caller: the event that
     * reports it describes that client, never the one a request bound in the
     * container comes from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallersClientDescribesTheStepUp(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $events  = [];

        $this->bindStrayRequest();

        Event::listen(SteppedUp::class, static function (SteppedUp $event) use (&$events): void {
            $events[] = $event;
        });

        self::assertTrue($this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, $this->signInReference($session)))->isIssued());
        self::assertCount(1, $events);
        self::assertSame([self::CLIENT_IP, self::CLIENT_AGENT], [$events[0]->context->client->ip, $events[0]->context->client->userAgent]);
    }

    /**
     * Rows of `[caller]` that are no active caller on the proof's application:
     * a pending caller, nobody, and a caller on another application.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Fixtures\Models\Person, string): \SineMacula\Laravel\Mfa\Context\CallerContext}>
     */
    public static function provideCallersThatAreNotTheSessions(): iterable
    {
        yield 'a pending caller' => [static fn (Person $person, string $signIn): CallerContext => CallerContext::forPending(self::pendingOf($person, $signIn))];

        yield 'nobody' => [static fn (): CallerContext => CallerContext::nobody(self::GUARD)];

        yield 'another application' => [static fn (Person $person): CallerContext => self::callerOf($person, 'another-application')];
    }

    /**
     * Only an active caller's session is stepped up, with a proof made on the
     * caller's application: any other caller is refused before anything is
     * read, and nothing is recorded.
     *
     * @param  \Closure(\Tests\Fixtures\Models\Person, string): \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCallersThatAreNotTheSessions')]
    public function testOnlyAnActiveCallersSessionIsSteppedUp(\Closure $caller): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $signIn  = $this->signInReference($session);

        $refusal = self::assertNotAccepted(fn (): mixed => $this->adapter()->stepUp($caller($person, $signIn), $this->verifiedResult($person, $signIn)));

        self::assertSame('Only an active caller\'s session is stepped up, with a proof made on its application.', $refusal->getMessage());
        self::assertCount(1, $this->proofsOf($session));
    }

    /**
     * A caller that is no active caller on the proof's application is refused
     * by throwing inside MFA's transaction, which rolls back what it wrote
     * before, though the guard serves the identity's session.
     *
     * @param  \Closure(\Tests\Fixtures\Models\Person, string): \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCallersThatAreNotTheSessions')]
    public function testACallerThatIsNotTheSessionsIsRefusedInsideTheTransaction(\Closure $caller): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $signIn  = $this->signInReference($session);

        self::assertNotAccepted(fn (): mixed => DB::transaction(function () use ($caller, $person, $signIn): AccessTokenResult {

            VerificationGeneration::advance($person);

            return $this->adapter()->stepUp($caller($person, $signIn), $this->verifiedResult($person, $signIn));
        }));

        self::assertSame(0, VerificationGeneration::current($person));
        self::assertCount(1, $this->proofsOf($session));
    }

    /**
     * The caller's application is the guard stepped up, never the default
     * guard: while the default guard is another, the caller's session on its
     * own application is stepped up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallersApplicationIsSteppedUpWhateverTheDefaultGuard(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        Config::set('auth.defaults.guard', 'web');

        self::assertTrue($this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, $this->signInReference($session)))->isIssued());
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

        self::assertTrue($this->adapter()->stepUp(self::callerOf($person), $result)->isIssued());

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

        $result  = $this->verifiedResult($this->createPerson(), $this->signInReference($session));
        $refusal = self::assertNotAccepted(fn (): mixed => $this->adapter()->stepUp(self::callerOf($person), $result));

        self::assertSame(self::NOT_BOUND, $refusal->getMessage());
        self::assertCount(1, $this->proofsOf($session));
    }

    /**
     * A proof bound to another of the identity's live sessions than the guard's
     * steps that session up, the sign-in MFA named, and the guard's session
     * records nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofOfAnotherOfTheIdentitysSessionsStepsThatSessionUp(): void
    {
        $person  = $this->createPerson();
        $other   = $this->signIn($person)->record;
        $session = $this->signInAndActOnSession($person);

        $token = $this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, $this->signInReference($other)));

        self::assertTrue($token->isIssued());
        self::assertSame($other->getSessionIdentifier(), $token->session?->getSessionIdentifier());
        self::assertCount(2, $this->proofsOf($other));
        self::assertCount(1, $this->proofsOf($session));
    }

    /**
     * A proof bound to another identity's session, though made by the caller,
     * is refused with `laravel-authentication`'s reason, and neither session
     * records it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofBoundToAnotherIdentitysSessionIsRefused(): void
    {
        $person   = $this->createPerson();
        $stranger = $this->signIn($this->createPerson())->record;
        $session  = $this->signInAndActOnSession($person);

        $refusal = self::assertNotAccepted(fn (): mixed => $this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, $this->signInReference($stranger))));

        self::assertSame('laravel-authentication refused the step-up: [proof_binding_mismatch].', $refusal->getMessage());
        self::assertCount(1, $this->proofsOf($stranger));
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

        $result  = $this->verifiedResult($person, $this->signInReference($session), Purpose::SIGN_IN);
        $refusal = self::assertNotAccepted(fn (): mixed => $this->adapter()->stepUp(self::callerOf($person), $result));

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

        $refusal = self::assertNotAccepted(fn (): mixed => $this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, $this->signInReference($session))));

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

        $result    = $this->verifiedResult($person, '1', application: $application);
        $exception = self::assertUnresolved(fn (): mixed => $this->adapter()->stepUp(self::callerOf($person, $application), $result), ReferenceKind::GUARD);

        self::assertSame($application, $exception->application);
        self::assertStringStartsWith(sprintf('The application [%s] is not a laravel-authentication guard', $application), $exception->getMessage());
    }

    /**
     * The session the proof is bound to is stepped up whatever the guard holds:
     * from a guard serving no one, as a queued job or a console command calls
     * MFA, and from a guard acting as the identity on no session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBoundSessionIsSteppedUpWhateverTheGuardHolds(): void
    {
        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;
        $signIn  = $this->signInReference($session);

        self::assertTrue($this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, $signIn))->isIssued());
        self::assertCount(2, $this->proofsOf($session));

        $this->actingAsIdentity($person, guard: self::GUARD);

        self::assertTrue($this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, $signIn))->isIssued());
        self::assertCount(3, $this->proofsOf($session));
    }

    /**
     * A proof bound to a sign-in no session holds is refused with
     * `laravel-authentication`'s reason, inside the transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofOfASignInNoSessionHoldsIsRefused(): void
    {
        $person = $this->createPerson();

        $refusal = self::assertNotAccepted(fn (): mixed => $this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, '987654')));

        self::assertSame('laravel-authentication refused the step-up: [session_unknown].', $refusal->getMessage());
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

            return $this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, $this->signInReference($session), Purpose::SIGN_IN));
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

                self::assertTrue($this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, $this->signInReference($session)))->isIssued());

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

            self::assertTrue($this->adapter()->stepUp(self::callerOf($person), $this->verifiedResult($person, $this->signInReference($session)))->isIssued());
        });

        self::assertNotSame([], array_filter($locks, static fn (string $sql): bool => str_contains($sql, $session->getTable())));
        self::assertSame([], array_filter($locks, static fn (string $sql): bool => str_contains($sql, 'mfa_')));
    }

    /**
     * The caller the kit's step-ups are handed: the kit's person, an active
     * caller on the guard.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     */
    #[\Override]
    protected function stepUpCaller(): CallerContext
    {
        return self::callerOf($this->kitPerson());
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
     * A successful result of the kit's person bound to a session that is not
     * one of theirs: another identity's live session.
     *
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function stepUpResultOfAnotherBinding(): VerificationResult
    {
        $person = $this->kitPerson();
        $other  = $this->signIn($this->createPerson())->record;

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
        $reference = ProofOwner::of($person);

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
     * A pending context of the person's on the sign-in given, as a pending
     * caller would be served it.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $signIn
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    private static function pendingOf(Person $person, string $signIn): PendingContext
    {
        $reference = ProofOwner::of($person);

        $firstFactor = new Proof(
            ProofKind::FIRST_FACTOR,
            'password',
            new Channel(ChannelKind::PASSWORD, null),
            null,
            ObservedProperties::none(),
            CarbonImmutable::now(),
            new ProofBinding($reference->type, $reference->key, self::GUARD, $signIn, Purpose::SIGN_IN),
            VerificationGeneration::current($person),
        );

        return new PendingContext($person, self::GUARD, $signIn, $firstFactor, Requirement::none()->withAdditionalVerification(), [], CarbonImmutable::now()->addMinutes(5));
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
     * The person the kit's step-ups are for, made once per test.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    private function kitPerson(): Person
    {
        return $this->kitPerson ??= $this->createPerson();
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
