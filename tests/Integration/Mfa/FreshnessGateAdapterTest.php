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
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\FreshnessGateTests;
use Tests\Concerns\MigratesMembers;
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
 * rolling back the transaction it is asked in; and it takes no lock.
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
    use FreshnessGateTests, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

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

        self::assertFalse($this->adapter()->isFresh(self::OPERATION, $asked));
        self::assertNull($this->adapter()->freshUntil(self::OPERATION, $asked));

        $this->stepSessionUp($person, $session);

        self::assertTrue($this->adapter()->isFresh(self::OPERATION, $asked));
        self::assertTrue($steppedUp->addSeconds(300)->equalTo($this->adapter()->freshUntil(self::OPERATION, $asked)));

        $this->travel(300)->seconds();

        self::assertFalse($this->adapter()->isFresh(self::OPERATION, $asked));
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

        self::assertTrue($this->adapter()->isFresh(self::OPERATION, $verification));
        self::assertFalse($this->adapter()->isFresh(self::OPERATION, $multifactor));
        self::assertFalse($this->adapter()->isFresh(self::OPERATION, $phishing));

        $this->stepSessionUp($person, $session);

        self::assertTrue($this->adapter()->isFresh(self::OPERATION, $multifactor));
        self::assertFalse($this->adapter()->isFresh(self::OPERATION, $phishing));

        $this->stepSessionUp($person, $session, phishingResistant: true);

        self::assertTrue($this->adapter()->isFresh(self::OPERATION, $phishing));
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

        self::assertTrue($first->addSeconds(300)->equalTo($this->adapter()->freshUntil(self::OPERATION, $asked)));

        $this->travel(200)->seconds();

        self::assertNull($this->adapter()->freshUntil(self::OPERATION, $asked));
        self::assertFalse($this->adapter()->isFresh(self::OPERATION, $asked));
        self::assertTrue($this->adapter()->isFresh(self::OPERATION, Requirement::none()->withAdditionalVerification(600)));
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

        self::assertTrue($this->adapter()->isFresh(Operations::IDENTIFIER_CHANGE));
        self::assertTrue($this->adapter()->isFresh(Operations::IDENTIFIER_CHANGE, Requirement::none()));
        self::assertFalse($this->adapter()->isFresh(Operations::IDENTIFIER_CHANGE, $asked));

        $this->stepSessionUp($person, $session);

        Config::set('authentication.freshness.' . Operations::IDENTIFIER_CHANGE . '.max_age_seconds', 60);

        self::assertTrue($this->adapter()->isFresh(Operations::IDENTIFIER_CHANGE, $asked));

        $this->travel(60)->seconds();

        self::assertFalse($this->adapter()->isFresh(Operations::IDENTIFIER_CHANGE, $asked));
        self::assertTrue($this->adapter()->isFresh(self::OPERATION, $asked));
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
        Config::set('auth.defaults.guard', 'not-a-guard');

        foreach (
            [
                fn (): mixed => $this->adapter()->isFresh(self::OPERATION, $requirement),
                fn (): mixed => $this->adapter()->freshUntil(self::OPERATION, $requirement),
                fn (): mixed => $this->adapter()->requirement(self::OPERATION, $requirement),
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

        self::assertFalse($this->adapter()->isFresh('Not An Operation', $unbounded));
        self::assertNull($this->adapter()->freshUntil('Not An Operation', $unbounded));
        self::assertNull($this->adapter()->requirement('Not An Operation', Requirement::none()->withAdditionalVerification(300)));
    }

    /**
     * A caller with no session is not fresh for any operation, though the
     * requirement for it is answered.
     *
     * @return void
     */
    public function testACallerWithNoSessionIsNotFresh(): void
    {
        self::assertFalse($this->adapter()->isFresh(Operations::IDENTIFIER_CHANGE));
        self::assertNull($this->adapter()->freshUntil(Operations::IDENTIFIER_CHANGE));
        self::assertNotNull($this->adapter()->requirement(Operations::FACTOR_CHANGE));
    }

    /**
     * Rows of `[default guard]` that are no guard of
     * `laravel-authentication`'s: a name no guard is declared under, Laravel's
     * own session guard, and none.
     *
     * @return iterable<string, array{0: ?string, 1: string}>
     */
    public static function provideDefaultGuardsThatAreNoAuthenticationGuard(): iterable
    {
        yield 'no guard' => ['not-a-guard', 'not-a-guard'];

        yield 'another kind of guard' => ['web', 'web'];

        yield 'none' => [null, ''];
    }

    /**
     * A default guard that is not one of `laravel-authentication`'s cannot be
     * resolved, and every question throws.
     *
     * @param  ?string  $guard
     * @param  string  $named
     * @return void
     */
    #[DataProvider('provideDefaultGuardsThatAreNoAuthenticationGuard')]
    public function testADefaultGuardThatIsNoAuthenticationGuardIsUnresolved(?string $guard, string $named): void
    {
        Config::set('auth.defaults.guard', $guard);

        foreach (
            [
                fn (): mixed => $this->adapter()->isFresh(Operations::IDENTIFIER_CHANGE),
                fn (): mixed => $this->adapter()->requirement(Operations::IDENTIFIER_CHANGE),
            ] as $question
        ) {

            try {
                $question();

                self::fail('A guard that is not laravel-authentication\'s was asked.');
            } catch (UnresolvedReferenceException $exception) {
                self::assertSame(ReferenceKind::GUARD, $exception->kind);
                self::assertSame($named, $exception->application);
            }
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

        self::assertSame($verification->toArray(), $this->adapter()->requirement(Operations::FACTOR_CHANGE)?->toArray());
        self::assertSame($verification->withMultifactor(300)->toArray(), $this->adapter()->requirement(Operations::FACTOR_CHANGE, $multifactor)?->toArray());

        self::assertNull($this->adapter()->requirement(Operations::IDENTIFIER_CHANGE));
        self::assertNull($this->adapter()->requirement(Operations::IDENTIFIER_CHANGE, Requirement::none()));
        self::assertSame($multifactor->toArray(), $this->adapter()->requirement(Operations::IDENTIFIER_CHANGE, $multifactor)?->toArray());

        Config::set('auth.guards.' . self::GUARD . '.freshness', [
            self::PAYOUTS => ['max_age_seconds' => 120, 'proofs' => ['first_factor', 'additional_factor'], 'multifactor' => true, 'phishing_resistant' => true],
        ]);

        self::assertSame(Requirement::none()->withMultifactor(120)->withPhishingResistance(120)->toArray(), $this->adapter()->requirement(self::PAYOUTS)?->toArray());
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

            return $this->adapter()->isFresh(self::OPERATION, Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, 300));
        }));

        self::assertSame(0, VerificationGeneration::current($person));
    }

    /**
     * Inside MFA's transaction, holding the identity's state row, the gate
     * reads without taking any lock, so it never takes one out of the order
     * identity state, factors, challenge, session row.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testItTakesNoLock(string $level): void
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

            self::assertTrue($this->adapter()->isFresh(self::OPERATION, Requirement::none()->withAdditionalVerification(300)->withMultifactor(300)));
        });

        self::assertNotSame([], $queries);
        self::assertSame([], array_filter($queries, static fn (string $sql): bool => preg_match('/\b(for update|for share|for no key update|lock in share mode)\b/i', $sql) === 1));
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
            new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-1'),
            'factor-1',
            new ObservedProperties(phishingResistant: $phishingResistant),
            new Evaluation(true, $multifactor),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($person, self::GUARD, $session->getSessionIdentifier(), Purpose::STEP_UP),
        ));

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
