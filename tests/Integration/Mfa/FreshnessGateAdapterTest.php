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
 * Integration tests for MFA's freshness gate over the freshness policy.
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
     * An additional verification is met by a step-up within its age.
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
     * Each flag is met only by a proof that shows it.
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
     * Every part must be met, and the session is fresh until the first lapses.
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
     * The application's setting makes the caller's requirement stricter.
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
     * Rows of `[requirement]` the policy cannot hold a session to.
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
     * A requirement the policy cannot judge is refused by every question.
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
     * A name that is no operation's is never fresh and has no requirement.
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
     * A caller with no session is not fresh.
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
     * Rows of `[application]` that are no guard of `laravel-authentication`'s.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideApplicationsThatAreNoAuthenticationGuard(): iterable
    {
        yield 'no guard' => ['not-a-guard'];

        yield 'another kind of guard' => ['web'];
    }

    /**
     * An application that is no authentication guard throws on every question.
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
     * The caller's application is asked, never the default guard.
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
     * Only an active caller whose guard holds its own session can be fresh.
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
     * The requirement is the stricter of the caller's and the setting's.
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
     * A refusal rolls back the transaction it is asked in.
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
     * Outside a transaction the gate asks the policy plainly and takes no lock.
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
     * Inside a transaction the gate asks the policy current.
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
     * Inside MFA's transaction the gate locks the session row last.
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
     * A step-up voided after the transaction's first read is not fresh.
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
     * A step-up made after the transaction's first read is fresh.
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
     * The caller the kit's gates are asked for.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     */
    #[\Override]
    protected function freshnessCaller(): CallerContext
    {
        return self::servedCaller();
    }

    /**
     * The gate under test, asked for a session that has just signed in.
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
     * A pending context of the person's on the sign-in.
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
     * Step the session up with a TOTP proof, failing unless it is recorded.
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
     * Assert the call is refused as a requirement the gate cannot take.
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
