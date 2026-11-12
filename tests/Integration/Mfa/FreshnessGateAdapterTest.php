<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\FreshnessGateAdapter;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Mfa\Assurance\Channel as MfaChannel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties as MfaObservedProperties;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind as MfaProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Proofs\Proof as MfaProof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding as MfaProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\FreshnessGateTests;
use Tests\Concerns\BindsStrayRequests;
use Tests\Concerns\ChangesSessionsElsewhere;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RecordsFreshnessReadModes;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for MFA's freshness gate over `laravel-authentication`'s
 * freshness policy (IAM-3.5): each part MFA asks for is judged by the policy on
 * the caller's session, made stricter by the application's own setting for the
 * operation, and the session is fresh until the first of them lapses; the
 * requirement it holds the session to is at least the caller's; a part the
 * policy cannot judge is refused; a caller with no session is not fresh; a
 * default guard that is not `laravel-authentication`'s throws (IAM-8.2),
 * rolling back the transaction it is asked in; outside a transaction it asks
 * the policy plainly and takes no lock; and inside one, as MFA's own
 * factor-change gate asks it inside MFA's transaction, it asks the policy
 * current, locking the session's row after MFA's locks, so a step-up voided or
 * made by another request after the transaction's first read is judged as
 * committed.
 *
 * The sessions are real ones, signed in through `laravel-authentication` with a
 * password and stepped up through it, and the adapter is resolved on its own,
 * so none of this package's other adapters takes part.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessGateAdapter::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class FreshnessGateAdapterTest extends TestCase
{
    use BindsStrayRequests, ChangesSessionsElsewhere, FreshnessGateTests, MigratesMembers, RecordsFreshnessReadModes, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The factor the tests' step-ups are made with. */
    private const string FACTOR = 'factor-1';

    /** @var string A locking read, of either server's grammar. */
    private const string LOCKING_READ = '/\b(for update|for share|for no key update|lock in share mode)\b/i';

    /** @var string An operation of MFA's that `laravel-authentication` configures no setting for. */
    private const string OPERATION = 'mfa.remove_factor';

    /** @var string An operation the application configures in `laravel-authentication` alone. */
    private const string PAYOUTS = 'payouts.change';

    /**
     * An additional verification is met by a step-up within its age, and the
     * session stays fresh until the step-up is as old as the age.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAdditionalVerificationIsMetByAStepUpWithinItsAge(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());

        $person    = $this->createPerson();
        $session   = $this->signInAndActOnSession($person);
        $asked     = Requirement::none()->withAdditionalVerification(300);
        $steppedUp = CarbonImmutable::now();

        self::assertFalse($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $asked));
        self::assertNull($this->adapter()->freshUntil(self::servedCaller(), self::OPERATION, $asked));

        $this->stepSessionUp($person, $session);

        self::assertTrue($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $asked));
        self::assertEquals($steppedUp->addSeconds(300), $this->adapter()->freshUntil(self::servedCaller(), self::OPERATION, $asked));

        $this->travel(300)->seconds();

        self::assertFalse($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $asked));
    }

    /**
     * Multifactor authentication is met only by a proof whose evaluation
     * reported it, and phishing resistance only by one observed to resist
     * phishing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachFlagIsMetOnlyByAProofThatShowsIt(): void
    {
        $person       = $this->createPerson();
        $session      = $this->signInAndActOnSession($person);
        $multifactor  = Requirement::none()->withMultifactor(300);
        $phishing     = Requirement::none()->withPhishingResistance(300);
        $verification = Requirement::none()->withAdditionalVerification(300);

        $this->stepSessionUp($person, $session, multifactor: false);

        self::assertTrue($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $verification));
        self::assertFalse($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $multifactor));
        self::assertFalse($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $phishing));

        $this->stepSessionUp($person, $session);

        self::assertTrue($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $multifactor));
        self::assertFalse($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $phishing));

        $this->stepSessionUp($person, $session, phishingResistant: true);

        self::assertTrue($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $phishing));
    }

    /**
     * With several parts asked for, every one must be met, and the session is
     * fresh until the first of them lapses.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFirstPartToLapseBoundsTheFreshness(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $asked   = Requirement::none()->withAdditionalVerification(600)->withMultifactor(300);
        $first   = CarbonImmutable::now();

        $this->stepSessionUp($person, $session);
        $this->travel(100)->seconds();
        $this->stepSessionUp($person, $session, multifactor: false);

        self::assertEquals($first->addSeconds(300), $this->adapter()->freshUntil(self::servedCaller(), self::OPERATION, $asked));

        $this->travel(200)->seconds();

        self::assertNull($this->adapter()->freshUntil(self::servedCaller(), self::OPERATION, $asked));
        self::assertFalse($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $asked));
        self::assertTrue($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, Requirement::none()->withAdditionalVerification(600)));
    }

    /**
     * The application's own setting for the operation decides alone when the
     * caller asks for nothing, and makes the caller's stricter when it asks for
     * something: the kinds both take, and the shorter age.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationsSettingMakesTheCallersStricter(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $asked   = Requirement::none()->withAdditionalVerification(600);

        self::assertTrue($this->adapter()->isFresh(self::servedCaller(), Operations::IDENTIFIER_CHANGE));
        self::assertTrue($this->adapter()->isFresh(self::servedCaller(), Operations::IDENTIFIER_CHANGE, Requirement::none()));
        self::assertFalse($this->adapter()->isFresh(self::servedCaller(), Operations::IDENTIFIER_CHANGE, $asked));

        $this->stepSessionUp($person, $session);

        Config::set('authentication.freshness.' . Operations::IDENTIFIER_CHANGE . '.max_age_seconds', 60);

        self::assertTrue($this->adapter()->isFresh(self::servedCaller(), Operations::IDENTIFIER_CHANGE, $asked));

        $this->travel(60)->seconds();

        self::assertFalse($this->adapter()->isFresh(self::servedCaller(), Operations::IDENTIFIER_CHANGE, $asked));
        self::assertTrue($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $asked));
    }

    /**
     * Rows of `[requirement]` the policy cannot hold a session to: a minimum
     * assurance level, which no proof records, and a part longer than a day.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Requirements\Requirement, 1: string}>
     */
    public static function provideRequirementsThePolicyCannotJudge(): iterable
    {
        yield 'a minimum level' => [
            Requirement::none()->withAdditionalVerification(300)->withMinimumLevel(AssuranceLevel::AAL2, 300),
            'laravel-authentication\'s freshness cannot hold a session to a minimum assurance level, which its proofs do not record:'
            . ' configure the operation\'s freshness without one, or bind a gate of your own that judges it.',
        ];

        yield 'longer than a day' => [Requirement::none()->withMultifactor(86401), 'A freshness requirement\'s maximum age must be from 1 to 86400 seconds.'];
    }

    /**
     * A caller's requirement the policy cannot hold the session to is refused,
     * by every question, before anything is read.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRequirementsThePolicyCannotJudge')]
    public function testARequirementThePolicyCannotJudgeIsRefused(Requirement $requirement, string $message): void
    {
        foreach (
            [
                fn (): mixed => $this->adapter()->isFresh(CallerContext::nobody('not-a-guard'), self::OPERATION, $requirement),
                fn (): mixed => $this->adapter()->freshUntil(CallerContext::nobody('not-a-guard'), self::OPERATION, $requirement),
                fn (): mixed => $this->adapter()->requirement(CallerContext::nobody('not-a-guard'), self::OPERATION, $requirement),
            ] as $question
        ) {
            self::assertSame($message, self::assertRefused($question)->getMessage());
        }
    }

    /**
     * A name that is not an operation's is never fresh and has no requirement,
     * whatever the caller asks, without the caller's requirement being looked
     * at.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANameThatIsNoOperationIsAnsweredFirst(): void
    {
        $this->signInAndActOnSession($this->createPerson());

        $unbounded = Requirement::none()->withAdditionalVerification();

        self::assertFalse($this->adapter()->isFresh(self::servedCaller(), 'Not An Operation', $unbounded));
        self::assertNull($this->adapter()->freshUntil(self::servedCaller(), 'Not An Operation', $unbounded));
        self::assertNull($this->adapter()->requirement(self::servedCaller(), 'Not An Operation', Requirement::none()->withAdditionalVerification(300)));
    }

    /**
     * A caller with no session is not fresh for any operation, though the
     * requirement for it is answered.
     *
     * @return void
     */
    public function testACallerWithNoSessionIsNotFresh(): void
    {
        self::assertFalse($this->adapter()->isFresh(self::servedCaller(), Operations::IDENTIFIER_CHANGE));
        self::assertNull($this->adapter()->freshUntil(self::servedCaller(), Operations::IDENTIFIER_CHANGE));
        self::assertNotNull($this->adapter()->requirement(self::servedCaller(), Operations::FACTOR_CHANGE));
    }

    /**
     * Rows of `[application]` that are no guard of `laravel-authentication`'s:
     * a name no guard is declared under, and Laravel's own session guard.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideApplicationsThatAreNoAuthenticationGuard(): iterable
    {
        yield 'no guard' => ['not-a-guard'];

        yield 'another kind of guard' => ['web'];
    }

    /**
     * A caller's application that is not one of `laravel-authentication`'s
     * guards cannot be resolved, and every question throws, whoever the caller
     * is.
     *
     * @param  string  $application
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideApplicationsThatAreNoAuthenticationGuard')]
    public function testAnApplicationThatIsNoAuthenticationGuardIsUnresolved(string $application): void
    {
        $person = $this->createPerson();

        foreach ([CallerContext::nobody($application), self::callerOf($person, $application)] as $caller) {
            foreach (
                [
                    fn (): mixed => $this->adapter()->isFresh($caller, Operations::IDENTIFIER_CHANGE),
                    fn (): mixed => $this->adapter()->requirement($caller, Operations::IDENTIFIER_CHANGE),
                ] as $question
            ) {

                try {
                    $question();

                    self::fail('A guard that is not laravel-authentication\'s was asked.');
                } catch (UnresolvedReferenceException $exception) {
                    self::assertSame(ReferenceKind::GUARD, $exception->kind);
                    self::assertSame($application, $exception->application);
                }
            }
        }
    }

    /**
     * The caller's own application is asked, never the default guard: the
     * guard's session of the caller's is judged, and its setting read, while
     * the default guard is another.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallersApplicationIsAsked(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        Config::set('auth.defaults.guard', 'web');

        self::assertTrue($this->adapter()->isFresh(self::callerOf($person), Operations::IDENTIFIER_CHANGE));
        self::assertNotNull($this->adapter()->requirement(self::callerOf($person), Operations::FACTOR_CHANGE));
    }

    /**
     * Only an active caller whose guard holds a session of its own can be
     * fresh: a caller the guard holds no session of (another identity than the
     * one it serves), a pending caller and nobody are not, though the
     * requirement for each is answered, and a request bound in the container
     * never stands in for the caller handed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyAnActiveCallersOwnSessionCanBeFresh(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $signIn  = $this->signInReference($session);
        $pending = CallerContext::forPending(self::pendingOf($person, $signIn));

        $this->bindStrayRequest();

        self::assertTrue($this->adapter()->isFresh(self::callerOf($person), Operations::IDENTIFIER_CHANGE));

        foreach ([self::callerOf($this->createPerson()), $pending, CallerContext::nobody(self::GUARD)] as $caller) {
            self::assertFalse($this->adapter()->isFresh($caller, Operations::IDENTIFIER_CHANGE));
            self::assertNull($this->adapter()->freshUntil($caller, Operations::IDENTIFIER_CHANGE));
            self::assertNotNull($this->adapter()->requirement($caller, Operations::FACTOR_CHANGE));
        }
    }

    /**
     * The requirement is the stricter of the caller's and what MFA can express
     * of the application's setting: a setting taking only further factors and
     * recovery codes is an additional verification, its flags are multifactor
     * authentication and phishing resistance, and a setting that also takes a
     * first factor, with no flag, expresses nothing.
     *
     * @return void
     */
    public function testTheRequirementIsTheStricterOfTheCallersAndTheSettingsExpressedParts(): void
    {
        $multifactor  = Requirement::none()->withMultifactor(300);
        $verification = Requirement::none()->withAdditionalVerification(900);

        self::assertSame($verification->toArray(), $this->adapter()->requirement(self::servedCaller(), Operations::FACTOR_CHANGE)?->toArray());
        self::assertSame($verification->withMultifactor(300)->toArray(), $this->adapter()->requirement(self::servedCaller(), Operations::FACTOR_CHANGE, $multifactor)?->toArray());

        self::assertNull($this->adapter()->requirement(self::servedCaller(), Operations::IDENTIFIER_CHANGE));
        self::assertNull($this->adapter()->requirement(self::servedCaller(), Operations::IDENTIFIER_CHANGE, Requirement::none()));
        self::assertSame($multifactor->toArray(), $this->adapter()->requirement(self::servedCaller(), Operations::IDENTIFIER_CHANGE, $multifactor)?->toArray());

        Config::set('auth.guards.' . self::GUARD . '.freshness', [
            self::PAYOUTS => ['max_age_seconds' => 120, 'proofs' => ['first_factor', 'additional_factor'], 'multifactor' => true, 'phishing_resistant' => true],
        ]);

        $payouts = Requirement::none()->withMultifactor(120)->withPhishingResistance(120);

        self::assertSame($payouts->toArray(), $this->adapter()->requirement(self::servedCaller(), self::PAYOUTS)?->toArray());
    }

    /**
     * A refusal inside MFA's transaction rolls back what the transaction wrote
     * before it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalRollsBackTheTransactionItIsAskedIn(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        self::assertRefused(fn (): mixed => DB::transaction(function () use ($person): bool {

            VerificationGeneration::advance($person);

            return $this->adapter()->isFresh(self::servedCaller(), self::OPERATION, Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, 300));
        }));

        self::assertSame(0, VerificationGeneration::current($person));
    }

    /**
     * Outside a transaction, as MFA's route gate and `Mfa::isFresh()` ask it,
     * nothing acts on the answer atomically: the gate asks the policy plainly,
     * which the policy answers there, and takes no lock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOutsideATransactionItAsksPlainlyAndTakesNoLock(): void
    {
        $person   = $this->createPerson();
        $session  = $this->signInAndActOnSession($person);
        $asked    = Requirement::none()->withAdditionalVerification(300)->withMultifactor(300);
        $recorder = $this->recordReadModes();
        $queries  = [];

        $this->stepSessionUp($person, $session);

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        self::assertSame(0, DB::transactionLevel());
        self::assertTrue($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $asked));
        self::assertNotNull($this->adapter()->freshUntil(self::servedCaller(), self::OPERATION, $asked));
        self::assertAskedOnlyIn($recorder, false);
        self::assertNotSame([], $queries);
        self::assertSame([], self::lockingReads($queries));
    }

    /**
     * Inside a transaction on the session model's connection, as MFA's own
     * factor-change gate asks it inside MFA's transaction and grants the change
     * on the answer, the gate asks the policy current, which the policy answers
     * there, both for whether the session is fresh and until when.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideATransactionItAsksCurrent(): void
    {
        $person   = $this->createPerson();
        $session  = $this->signInAndActOnSession($person);
        $asked    = Requirement::none()->withAdditionalVerification(300)->withMultifactor(300);
        $recorder = $this->recordReadModes();

        $this->stepSessionUp($person, $session);

        [$fresh, $until] = DB::transaction(fn (): array => [
            $this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $asked),
            $this->adapter()->freshUntil(self::servedCaller(), self::OPERATION, $asked),
        ]);

        self::assertTrue($fresh);
        self::assertNotNull($until);
        self::assertAskedOnlyIn($recorder, true);
    }

    /**
     * Inside MFA's transaction, holding the identity's state row, the gate's
     * current read locks the session's row and then reads its proofs, and takes
     * no lock of MFA's, so it never takes one out of the order identity state,
     * factors, challenge, session row.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testInsideMfasTransactionItLocksTheSessionRowLast(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $queries = [];

        $this->stepSessionUp($person, $session);

        DB::transaction(function () use ($person, &$queries): void {

            VerificationGeneration::advance($person);

            DB::listen(static function (QueryExecuted $query) use (&$queries): void {
                $queries[] = $query->sql;
            });

            self::assertTrue($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, Requirement::none()->withAdditionalVerification(300)->withMultifactor(300)));
        });

        $locks = self::lockingReads($queries);

        self::assertNotSame([], $locks);
        self::assertStringContainsString($session->getTable(), $locks[0]);
        self::assertSame([], array_filter($locks, static fn (string $sql): bool => !str_contains($sql, 'authentication_')));
        self::assertSame([], array_filter($queries, static fn (string $sql): bool => str_contains($sql, 'mfa_')));
    }

    /**
     * Inside a caller's transaction that read before another request voided the
     * session's step-up (removing the factor it was made with), the session is
     * not fresh: the step-up is judged as committed, never as the transaction's
     * snapshot shows it, which on MySQL at REPEATABLE READ still holds it. On
     * PostgreSQL at REPEATABLE READ the session's lock fails to serialise
     * first, and the question asked again in a new transaction is answered the
     * same.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAStepUpVoidedAfterTheTransactionsFirstReadIsNotFresh(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $asked   = Requirement::none()->withAdditionalVerification(300);

        $this->stepSessionUp($person, $session);

        self::assertTrue($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $asked));

        $answers = $this->askedAfter(
            $level,
            fn () => $this->removeElsewhere($person, $session, self::FACTOR),
            fn (): array => [$this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $asked), $this->adapter()->freshUntil(self::servedCaller(), self::OPERATION, $asked)],
        );

        self::assertSame([false, null], $answers);
    }

    /**
     * Inside a caller's transaction that read before another request stepped
     * the session up, the session is fresh on that step-up, which the
     * transaction's snapshot on MySQL at REPEATABLE READ does not hold. On
     * PostgreSQL at REPEATABLE READ the session's lock fails to serialise
     * first, and the question asked again in a new transaction is answered the
     * same.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAStepUpMadeAfterTheTransactionsFirstReadIsFresh(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $asked   = Requirement::none()->withAdditionalVerification(300);

        self::assertFalse($this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $asked));

        $fresh = $this->askedAfter(
            $level,
            fn () => $this->elsewhere(fn () => $this->stepSessionUp($person, $session)),
            fn (): bool => $this->adapter()->isFresh(self::servedCaller(), self::OPERATION, $asked),
        );

        self::assertTrue($fresh);
    }

    /**
     * The gate under test, asked on behalf of a signed-in person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function freshnessGate(): FreshnessGate
    {
        $this->signInAndActOnSession($this->createPerson());

        return $this->adapter();
    }

    /**
     * The caller the kit's gates are asked for: the person the guard serves on
     * the session `freshnessGate()` signed in, as a request served now reads
     * it.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     */
    #[\Override]
    protected function freshnessCaller(): CallerContext
    {
        return self::servedCaller();
    }

    /**
     * The gate under test, asked on behalf of a session that has just signed
     * in, which is fresh for an identifier change.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function freshGate(): FreshnessGate
    {
        return $this->freshnessGate();
    }

    /**
     * An operation a session that has just signed in is fresh for.
     *
     * @return string
     */
    #[\Override]
    protected function freshOperation(): string
    {
        return Operations::IDENTIFIER_CHANGE;
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

        $firstFactor = new MfaProof(
            MfaProofKind::FIRST_FACTOR,
            'password',
            new MfaChannel(MfaChannelKind::PASSWORD, null),
            null,
            MfaObservedProperties::none(),
            CarbonImmutable::now(),
            new MfaProofBinding($reference->type, $reference->key, self::GUARD, $signIn, MfaPurpose::SIGN_IN),
            VerificationGeneration::current($person),
        );

        return new PendingContext($person, self::GUARD, $signIn, $firstFactor, Requirement::none()->withAdditionalVerification(), [], CarbonImmutable::now()->addMinutes(5));
    }

    /**
     * Step the session up with a TOTP proof of the person's, through
     * `laravel-authentication`, failing the test unless it is recorded.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  bool  $multifactor
     * @param  bool  $phishingResistant
     * @return void
     *
     * @throws \Throwable
     */
    private function stepSessionUp(Person $person, EloquentSession&Model $session, bool $multifactor = true, bool $phishingResistant = false): void
    {
        $result = $this->sessions()->stepUp(new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP, self::FACTOR),
            self::FACTOR,
            new ObservedProperties(phishingResistant: $phishingResistant),
            new Evaluation(true, $multifactor),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($person, self::GUARD, $session->getSessionIdentifier(), Purpose::STEP_UP),
        ), self::client());

        self::assertTrue($result->isIssued(), sprintf('The session was not stepped up: [%s].', $result->reason?->value));
    }

    /**
     * Assert the call is refused as a requirement the gate cannot take, and
     * return the refusal.
     *
     * @param  \Closure(): mixed  $call
     * @return \InvalidArgumentException
     */
    private static function assertRefused(\Closure $call): \InvalidArgumentException
    {
        try {
            $call();
        } catch (\InvalidArgumentException $exception) {
            return $exception;
        }

        self::fail('The requirement was not refused.');
    }

    /**
     * The locking reads among the statements.
     *
     * @param  list<string>  $queries
     * @return list<string>
     */
    private static function lockingReads(array $queries): array
    {
        return array_values(array_filter($queries, static fn (string $sql): bool => preg_match(self::LOCKING_READ, $sql) === 1));
    }

    /**
     * Resolve the adapter under test from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\FreshnessGateAdapter
     */
    private function adapter(): FreshnessGateAdapter
    {
        $adapter = $this->app?->make(FreshnessGateAdapter::class);

        self::assertInstanceOf(FreshnessGateAdapter::class, $adapter);

        return $adapter;
    }
}
