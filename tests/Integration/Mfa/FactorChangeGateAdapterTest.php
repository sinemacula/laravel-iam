<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\FactorChangeGateAdapter;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\FactorChangeGateTests;
use Tests\Concerns\ChangesSessionsElsewhere;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for MFA's factor-change gate through authentication's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeGateAdapter::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class FactorChangeGateAdapterTest extends TestCase
{
    use ArrangesFactorChanges, ChangesSessionsElsewhere, FactorChangeGateTests, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var int How long `laravel-authentication`'s factor changes stay fresh after a step-up by default, in seconds. */
    private const int FACTOR_CHANGE_SECONDS = 900;

    /** @var string The factor a removal names. */
    private const string REMOVED = 'factor-removed';

    /** @var string The factor a step-up is made with. */
    private const string STEPPED_UP = 'factor-stepped-up';

    /**
     * An allowed change lasts until the session stops being fresh for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAllowedChangeLastsUntilTheSessionStopsBeingFresh(): void
    {
        $now = CarbonImmutable::now()->startOfSecond();

        CarbonImmutable::setTestNow($now);

        $configured = $this->steppedUpChange(FactorChange::ADD_FACTOR, self::configuredRequirement());

        self::assertEquals($now->addSeconds(self::FACTOR_CHANGE_SECONDS), $this->gate()->authorize($configured));

        $shorter = $this->steppedUpChange(FactorChange::ADD_FACTOR, Requirement::none()->withAdditionalVerification(60));

        self::assertEquals($now->addSeconds(60), $this->gate()->authorize($shorter));
    }

    /**
     * Rows of `[MFA's requirement, whether a TOTP step-up reported multifactor allows a further factor]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Requirements\Requirement, 1: bool}>
     */
    public static function provideRequirements(): iterable
    {
        yield 'asks for nothing' => [Requirement::none(), true];

        yield 'an additional verification' => [Requirement::none()->withAdditionalVerification(600), true];

        yield 'multifactor' => [Requirement::none()->withMultifactor(600), true];

        yield 'multifactor of any age' => [Requirement::none()->withMultifactor(), true];

        yield 'multifactor within longer than a day' => [Requirement::none()->withMultifactor(200000), true];

        yield 'phishing resistance' => [Requirement::none()->withPhishingResistance(600), false];

        yield 'an additional verification, and phishing resistance' => [Requirement::none()->withAdditionalVerification(600)->withPhishingResistance(600), false];
    }

    /**
     * MFA's requirement is held to what a stored proof can show.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  bool  $allowed
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRequirements')]
    public function testMfasRequirementIsHeldToWhatAStoredProofCanShow(Requirement $requirement, bool $allowed): void
    {
        $change = $this->steppedUpChange(FactorChange::ADD_FACTOR, $requirement);

        self::assertSame($allowed, $this->isAllowed($change));
    }

    /**
     * The shortest age of the requirement's parts binds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheShortestAgeOfTheRequirementsPartsBinds(): void
    {
        $change = $this->steppedUpChange(FactorChange::ADD_FACTOR, Requirement::none()->withAdditionalVerification(600)->withMultifactor(60));

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(120));

        self::assertFalse($this->isAllowed($change));
    }

    /**
     * An additional verification takes a further factor or a recovery code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAdditionalVerificationTakesOnlyAFurtherFactorOrARecoveryCode(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->reauthenticate($person, $session);

        self::assertTrue($this->isAllowed($this->request($person, $session, FactorChange::ADD_FIRST_ADDITIONAL_FACTOR)));
        self::assertFalse($this->isAllowed($this->request($person, $session, FactorChange::ADD_FIRST_ADDITIONAL_FACTOR, Requirement::none()->withAdditionalVerification(600))));
    }

    /**
     * A minimum assurance level is refused as a misconfiguration.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMinimumLevelIsRefusedAsAMisconfiguration(): void
    {
        $change = $this->steppedUpChange(FactorChange::ADD_FACTOR, Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, 600));

        $message = 'laravel-authentication\'s freshness cannot hold a session to a minimum assurance level, which its proofs do not record:'
            . ' configure the operation\'s freshness without one, or bind a gate of your own that judges it.';

        $this->expectExceptionObject(new \InvalidArgumentException($message));

        $this->gate()->authorize($change);
    }

    /**
     * A session no longer live is refused as not fresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionNoLongerLiveIsNotFresh(): void
    {
        $change = $this->steppedUpChange(FactorChange::GENERATE_RECOVERY_CODES, null);

        Session::query()->whereKey($change->session)->update(['revoked_at' => CarbonImmutable::now()]);

        try {
            $this->gate()->authorize($change);

            self::fail('A change was allowed from a revoked session.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_FRESH, $exception->reason);
            self::assertFalse($exception->byPackage);
            self::assertSame('laravel-authentication refused the change [mfa.generate_recovery_codes] from the session: [session_revoked].', $exception->getMessage());
        }
    }

    /**
     * The change is judged on `laravel-authentication`'s verdict alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeIsJudgedOnLaravelAuthenticationsVerdictAlone(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $change  = $this->request($person, $session, FactorChange::REMOVE_FACTOR, self::configuredRequirement());
        $reads   = [];

        $this->stepUpWith($person, $session, self::STEPPED_UP);

        for ($stepUp = 0; $stepUp < RequirementSubject::MAX_LIMIT; $stepUp++) {
            $this->stepUpWith($person, $session, self::REMOVED);
        }

        DB::listen(static function (QueryExecuted $query) use (&$reads): void {

            if (!str_contains($query->sql, 'authentication_proofs')) {
                return;
            }

            $reads[] = $query->sql;
        });

        self::assertTrue($this->isAllowed($change));
        self::assertCount(1, $reads, implode("\n", $reads));
    }

    /**
     * A step-up voided after the first read never allows the change.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAStepUpVoidedAfterTheTransactionsFirstReadNeverAllowsAChange(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $change  = $this->request($person, $session, FactorChange::ADD_FACTOR, self::configuredRequirement());

        $this->stepUpWith($person, $session, self::STEPPED_UP);

        self::assertTrue($this->isAllowed($change));

        $refusal = $this->askedAfter(
            $level,
            fn () => $this->removeElsewhere($person, $session, self::STEPPED_UP),
            fn (): ?string => $this->refusalOf($change),
        );

        self::assertSame('laravel-authentication refused the change [mfa.add_factor] from the session: [step_up_required].', $refusal);
    }

    /**
     * A step-up made after the transaction's first read allows the change.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAStepUpMadeAfterTheTransactionsFirstReadAllowsAChange(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $change  = $this->request($person, $session, FactorChange::ADD_FACTOR, self::configuredRequirement());

        self::assertFalse($this->isAllowed($change));

        $refusal = $this->askedAfter(
            $level,
            fn () => $this->elsewhere(fn () => $this->stepUpWith($person, $session, self::STEPPED_UP)),
            fn (): ?string => $this->refusalOf($change),
        );

        self::assertNull($refusal);
    }

    /**
     * A change without the identity's session is refused and rolls back.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAChangeWithoutTheIdentitysSessionIsRefusedAndRollsBack(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person   = $this->createPerson();
        $current  = $this->signInAndActOnSession($person);
        $foreign  = $this->signIn($this->createPerson())->record;
        $stranger = new class extends User implements MultiFactorAuthenticatable {
            use HasFactors;
        };

        $this->stepUpWith($person, $current, self::STEPPED_UP);

        $requests = [
            $this->request($person, $foreign, FactorChange::ADD_FACTOR),
            new FactorChangeRequest($person, self::GUARD, '987654', FactorChange::ADD_FACTOR, new Collection),
            new FactorChangeRequest($stranger, self::GUARD, 'sign-in', FactorChange::ADD_FACTOR, new Collection),
            new FactorChangeRequest($person, 'web', $this->signInReference($current), FactorChange::ADD_FACTOR, new Collection),
        ];

        foreach ($requests as $request) {
            $this->assertRolledBack($person, UnresolvedReferenceException::class, $request);
        }
    }

    /**
     * A change is gated on the sign-in MFA names, never the guard's session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeIsGatedOnTheNamedSignInWhateverTheGuardHolds(): void
    {
        $person  = $this->createPerson();
        $other   = $this->signIn($person)->record;
        $current = $this->signInAndActOnSession($person);

        $this->stepUpWith($person, $other, self::STEPPED_UP);

        self::assertTrue($this->isAllowed($this->request($person, $other, FactorChange::ADD_FACTOR)));
        self::assertFalse($this->isAllowed($this->request($person, $current, FactorChange::ADD_FACTOR)));

        $this->stopActing(self::GUARD);

        self::assertTrue($this->isAllowed($this->request($person, $other, FactorChange::ADD_FACTOR)));
    }

    /**
     * The session's row is held until the caller's transaction ends.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testTheSessionsRowIsHeldUntilTheCallersTransactionEnds(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $change = $this->steppedUpChange(FactorChange::GENERATE_RECOVERY_CODES, null);
        $other  = $this->otherConnection();

        self::storage()->transaction(function () use ($change, $other): void {

            $this->gate()->authorize($change);

            self::assertFalse(self::canLock($other, $change->session), 'The session\'s row was not held by the caller\'s transaction.');
        });

        self::assertTrue(self::canLock($other, $change->session), 'The session\'s row was held once the caller\'s transaction ended.');
    }

    /**
     * Enrolling a further factor through MFA is gated after MFA's locks.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testEnrollingAFurtherFactorThroughMfaIsGatedAfterMfasLocks(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $factor  = $this->confirmedFactor($person);

        $this->bindTheFactorChangeAdapters();
        $this->nameTheSignIn($person, $session);

        self::assertSame(FailureReason::NOT_FRESH, Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::totp('ada@example.test'))->reason);
        self::assertSame(1, Factor::query()->count());

        $this->stepUpWith($person, $session, $factor->id);

        DB::enableQueryLog();

        $start = Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::totp('ada@example.test'));

        $locks = array_values(array_filter(
            array_column(DB::getQueryLog(), 'query'),
            static fn (string $query): bool => str_contains($query, 'for update'),
        ));

        $sessions = array_keys(array_filter($locks, static fn (string $query): bool => str_contains($query, 'authentication_sessions')));
        $members  = array_keys(array_filter($locks, static fn (string $query): bool => str_contains($query, 'mfa_identity_states') || str_contains($query, 'mfa_factors')));

        self::assertTrue($start->hasStarted(), $start->reason->value ?? '');
        self::assertSame(2, Factor::query()->count());
        self::assertNotSame([], $members);
        self::assertNotSame([], $sessions);
        self::assertGreaterThan(max($members), min($sessions));
    }

    /**
     * The storage connection MFA's transactions run on.
     *
     * @return \Illuminate\Database\Connection
     */
    public static function storageConnection(): Connection
    {
        return self::storage();
    }

    /**
     * The gate under test, asked inside a transaction.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorChangeGate
     */
    #[\Override]
    protected function factorChangeGate(): FactorChangeGate
    {
        $gate = $this->gate();

        return new readonly class ($gate) implements FactorChangeGate {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Iam\Mfa\FactorChangeGateAdapter  $gate
             */
            public function __construct(

                /** The gate asked inside the transaction. */
                private FactorChangeGateAdapter $gate,
            ) {}

            /**
             * Ask the gate inside a transaction on the storage connection.
             *
             * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
             * @return \Carbon\CarbonImmutable
             *
             * @throws \Throwable
             */
            #[\Override]
            public function authorize(FactorChangeRequest $request): CarbonImmutable
            {
                return FactorChangeGateAdapterTest::storageConnection()->transaction(fn (): CarbonImmutable => $this->gate->authorize($request));
            }
        };
    }

    /**
     * The change from a session fresh enough for it.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function freshChange(FactorChange $change): FactorChangeRequest
    {
        if ($change === FactorChange::ADD_FIRST_ADDITIONAL_FACTOR) {

            $person  = $this->createPerson();
            $session = $this->signInAndActOnSession($person);

            $this->reauthenticate($person, $session);

            return $this->request($person, $session, $change);
        }

        return $this->steppedUpChange($change, self::configuredRequirement());
    }

    /**
     * The change from a session only signed in.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function staleChange(FactorChange $change): FactorChangeRequest
    {
        $person = $this->createPerson();

        $requirement = $change->operation() === null ? null : self::configuredRequirement();

        return $this->request($person, $this->signInAndActOnSession($person), $change, $requirement);
    }

    /**
     * The removal of a factor from a session stepped up only with it.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function removalSteppedUpOnlyWithTheFactor(): FactorChangeRequest
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $removed = $this->confirmedFactor($person);

        $this->confirmedFactor($person);
        $this->stepUpWith($person, $session, $removed->id);

        return new FactorChangeRequest(
            $person,
            self::GUARD,
            $this->signInReference($session),
            FactorChange::REMOVE_FACTOR,
            $this->factorsOf($person),
            $removed->id,
            self::configuredRequirement(),
        );
    }

    /**
     * A fresh change carrying a requirement a TOTP step-up never shows.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function changeBeyondTheConfiguredRequirement(): FactorChangeRequest
    {
        return $this->steppedUpChange(FactorChange::GENERATE_RECOVERY_CODES, Requirement::none()->withPhishingResistance(self::FACTOR_CHANGE_SECONDS));
    }

    /**
     * The requirement MFA configures for factor changes by default.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    private static function configuredRequirement(): Requirement
    {
        return Requirement::none()->withAdditionalVerification(self::FACTOR_CHANGE_SECONDS);
    }

    /**
     * The change from a new person's session, freshly stepped up.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     *
     * @throws \Throwable
     */
    private function steppedUpChange(FactorChange $change, ?Requirement $requirement): FactorChangeRequest
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->stepUpWith($person, $session, self::STEPPED_UP);

        return $this->request($person, $session, $change, $requirement);
    }

    /**
     * The change from the session, naming the removed factor when there is one.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     */
    private function request(Person $person, EloquentSession&Model $session, FactorChange $change, ?Requirement $requirement = null): FactorChangeRequest
    {
        $factorId = $change->namesFactor() ? self::REMOVED : null;

        return new FactorChangeRequest($person, self::GUARD, $this->signInReference($session), $change, $this->factorsOf($person), $factorId, $requirement);
    }

    /**
     * The person's factors, as MFA hands them to the gate.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     */
    private function factorsOf(Person $person): Collection
    {
        $model = Mfa::factorModel();

        return $model::query()->where('authenticatable_id', (string) $person->id)->get();
    }

    /**
     * Whether the gate allows the change.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $change
     * @return bool
     *
     * @throws \Throwable
     */
    private function isAllowed(FactorChangeRequest $change): bool
    {
        try {
            $this->factorChangeGate()->authorize($change);
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_FRESH, $exception->reason);

            return false;
        }

        return true;
    }

    /**
     * The detail of the gate's refusal of the change, or `null` when allowed.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $change
     * @return ?string
     *
     * @throws \Throwable
     */
    private function refusalOf(FactorChangeRequest $change): ?string
    {
        try {
            $this->gate()->authorize($change);
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_FRESH, $exception->reason);

            return $exception->getMessage();
        }

        return null;
    }

    /**
     * Assert the change is refused with the exception given and rolls back.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  class-string<\RuntimeException>  $refusal
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return void
     *
     * @throws \Throwable
     */
    private function assertRolledBack(Person $person, string $refusal, FactorChangeRequest $request): void
    {
        try {
            self::storage()->transaction(function () use ($person, $request): void {

                $person->forceFill(['name' => 'Changed'])->save();

                $this->gate()->authorize($request);
            });

            self::fail('A change was allowed without a session of the identity\'s.');
        } catch (\RuntimeException $exception) {
            self::assertInstanceOf($refusal, $exception);
        }

        self::assertSame('Ada Lovelace', $person->refresh()->name);
    }

    /**
     * Open a second connection to the storage connection's database.
     *
     * @return \PDO
     */
    private function otherConnection(): \PDO
    {
        /** @var array{driver: string, host: string, port: string, database: string, username: string, password: string} $config */
        $config = Config::get('database.connections.' . self::CONNECTION);

        return new \PDO(
            sprintf('%s:host=%s;port=%s;dbname=%s', $config['driver'], $config['host'], $config['port'], $config['database']),
            $config['username'],
            $config['password'],
            [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION],
        );
    }

    /**
     * Whether the other connection can lock the session's row without waiting.
     *
     * @param  \PDO  $other
     * @param  string  $session
     * @return bool
     */
    private static function canLock(\PDO $other, string $session): bool
    {
        $other->beginTransaction();

        try {
            $statement = $other->prepare('select id from authentication_sessions where id = ? for update nowait');

            $statement->execute([$session]);

            return $statement->fetchColumn() !== false;
        } catch (\PDOException) {
            return false;
        } finally {
            $other->rollBack();
        }
    }

    /**
     * Resolve the gate under test from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\FactorChangeGateAdapter
     */
    private function gate(): FactorChangeGateAdapter
    {
        $gate = $this->app?->make(FactorChangeGateAdapter::class);

        self::assertInstanceOf(FactorChangeGateAdapter::class, $gate);

        return $gate;
    }
}
