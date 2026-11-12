<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\ConcurrencyErrorDetector;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\Events\ConnectionEvent;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Iam\Mfa\FactorChangeGateAdapter;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter;
use SineMacula\Laravel\Iam\Mfa\StepUpAdapter;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Races MFA's factor changes against step-ups and each other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeGateAdapter::class)]
#[CoversClass(SessionRevokerAdapter::class)]
#[CoversClass(StepUpAdapter::class)]
#[CoversClass(ProofStoreAdapter::class)]
final class FactorChangeLockOrderTest extends TestCase
{
    use ArrangesFactorChanges, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The connection the worker runs on, which the test never opens. */
    private const string RACER = 'racer';

    /** @var string The connection the test watches the worker's lock wait through. */
    private const string OBSERVER = 'observer';

    /** @var int How long to wait between looks at the worker, in microseconds: longer than the tenth of a second MySQL serves `innodb_trx` from a cache. */
    private const int POLL_INTERVAL = 150000;

    /** @var int How many times to look for the worker waiting on the lock. */
    private const int POLLS = 100;

    /** @var int How long to wait for the worker's word, in seconds. */
    private const int WORKER_TIMEOUT = 30;

    /** @var string What the worker reports when its side went ahead. */
    private const string ALLOWED = 'allowed';

    /** @var string What the worker reports when its transaction failed to serialise. */
    private const string SERIALISATION_FAILURE = 'serialisation failure';

    /** @var string The SQLSTATE of a transaction that failed to serialise. */
    private const string SERIALISATION_STATE = '40001';

    /** @var string A step-up of a session through `laravel-authentication`. */
    private const string STEP_UP = 'step-up';

    /** @var string A reauthentication of a session with the person's password. */
    private const string REAUTHENTICATION = 'reauthentication';

    /** @var string A proof made directly through `laravel-authentication`, its own transaction the outermost. */
    private const string DIRECTLY = 'directly';

    /** @var string A proof made inside a transaction the caller opened. */
    private const string IN_A_TRANSACTION = 'in a transaction';

    /** @var string A proof made inside `Iam::transaction()`. */
    private const string IN_IAM_TRANSACTION = 'in Iam::transaction()';

    /** @var string What the worker is told once it is to go on. */
    private const string GO = 'go';

    /** @var string The address the delivered codes go to. */
    private const string DESTINATION = 'ada@example.test';

    /** @var string MFA's table of the identity's state, its first lock. */
    private const string IDENTITY_STATE = 'mfa_identity_states';

    /** @var string MFA's table of the identity's factors, its second lock. */
    private const string FACTORS = 'mfa_factors';

    /** @var string `laravel-authentication`'s table of sessions, whose row is the one both members take. */
    private const string SESSIONS = 'authentication_sessions';

    /** @var string `laravel-authentication`'s table of the proofs recorded on each session. */
    private const string PROOFS = 'authentication_proofs';

    /** @var list<string> MFA's tables of an identity's own rows, which only a holder of the identity's state takes. */
    private const array IDENTITY_TABLES = [
        self::IDENTITY_STATE,
        self::FACTORS,
        'mfa_codes',
        'mfa_enrollments',
        'mfa_passkey_associations',
        'mfa_recovery_codes',
    ];

    /** @var list<array{level: int, sql: string, bindings: list<string>}> The statements recorded on the storage connection, each with the transaction level it ran at and its bindings. */
    private array $statements = [];

    /** @var bool Whether statements are being recorded. */
    private bool $recording = false;

    /** @var int The transaction level of the storage connection, as its events report it. */
    private int $level = 0;

    /** @var int How many outermost transactions the storage connection began while statements were recorded. */
    private int $outermost = 0;

    /**
     * A step-up waiting on a removal resumes and is refused.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAStepUpWaitingOnARemovalResumesAgainstIt(string $level): void
    {
        $this->needsARace($level);

        [$person, [$session]] = $this->arrange(1);
        [$removed, $kept]     = $this->factorsOf($person);

        $this->stepUpWith($person, $session, $kept->id);
        $this->requirePhishingResistance();

        $key = $this->signInReference($session);

        $outcome = $this->race(
            static fn (): bool => Mfa::removeFactor(self::servedCaller(), $removed->id)->wasMade(),
            function () use ($key, $kept): string {

                $session = Session::query()->findOrFail($key);
                $person  = $session->authenticatable;

                self::assertInstanceOf(Person::class, $person);

                return $this->stepUp($person, $session, $kept->id)->reason->value ?? self::ALLOWED;
            },
            $level,
        );

        self::assertSame(self::canGoOnAgainstTheOtherSide($level) ? 'session_pending' : self::SERIALISATION_FAILURE, $outcome);
        self::assertSame(SessionStatus::PENDING, Session::query()->findOrFail($key)->getStatus());
        self::assertNull(Factor::query()->find($removed->id));
    }

    /**
     * A removal waiting on a step-up resumes and is allowed.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARemovalWaitingOnAStepUpResumesAgainstIt(string $level): void
    {
        $this->needsARace($level);

        [$person, [$current, $other]] = $this->arrange(2);
        [$removed, $kept]             = $this->factorsOf($person);

        $outcome = $this->race(
            fn () => $this->stepUpWith($person, $current, $kept->id),
            fn (): string => $this->removeOn($this->signInReference($current), $removed->id),
            $level,
        );

        $made = self::canGoOnAgainstTheOtherSide($level);

        self::assertSame($made ? self::ALLOWED : self::SERIALISATION_FAILURE, $outcome);
        $this->assertRemovalKept($made, $current, $other, $removed);
    }

    /**
     * A factor change waiting on a removal resumes against what it left.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAFactorChangeWaitingOnARemovalResumesAgainstIt(string $level): void
    {
        $this->needsARace($level);

        [$person, [$session]] = $this->arrange(1);
        [$removed, $kept]     = $this->factorsOf($person);

        $this->stepUpWith($person, $session, $kept->id);

        $key = $this->signInReference($session);

        $outcome = $this->race(
            static fn (): bool => Mfa::removeFactor(self::servedCaller(), $removed->id)->wasMade(),
            function () use ($key): string {

                $this->actingOnSession(Session::query()->findOrFail($key));

                return Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::totp(self::DESTINATION))->reason->value ?? self::ALLOWED;
            },
            $level,
        );

        $started = self::canGoOnAgainstTheOtherSide($level);

        self::assertSame($started ? self::ALLOWED : self::SERIALISATION_FAILURE, $outcome);
        self::assertNull(Factor::query()->find($removed->id));
        self::assertSame(SessionStatus::ACTIVE, Session::query()->findOrFail($key)->getStatus());
        self::assertSame($started ? 1 : 0, Factor::query()->where('status', FactorStatus::PENDING->value)->count());
    }

    /**
     * A removal that fails to serialise is made when the request is retried.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARemovalThatFailsToSerialiseIsMadeWhenTheCallerRetriesTheRequest(string $level): void
    {
        $this->needsARace($level);

        [$person, [$current, $other]] = $this->arrange(2);
        [$removed, $kept]             = $this->factorsOf($person);

        $key = $this->signInReference($current);

        $outcome = $this->race(
            fn () => $this->stepUpWith($person, $current, $kept->id),
            fn (): string => $this->removeRetryingTheRequest($key, $removed->id),
            $level,
        );

        self::assertSame(sprintf('%s at attempt %d', self::ALLOWED, self::canGoOnAgainstTheOtherSide($level) ? 1 : 2), $outcome);
        $this->assertRemovalKept(true, $current, $other, $removed);
    }

    /**
     * A wrapped removal is never allowed on a step-up voided while it waited.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAWrappedRemovalIsNeverAllowedOnAStepUpVoidedWhileItWaited(string $level): void
    {
        $this->needsARace($level);

        [$person, [$session]] = $this->arrange(1);
        [$first, $second]     = $this->factorsOf($person);

        $this->confirmedFactor($person);
        $this->stepUpWith($person, $session, $first->id);
        $this->stepUpWith($person, $session, $second->id);

        $key = $this->signInReference($session);

        $outcome = $this->race(
            static fn (): string => self::remove($first->id),
            function () use ($key, $second): string {

                $attempts = 0;
                $refusals = $this->recordGateRefusals();

                $this->actingOnSession(Session::query()->findOrFail($key));

                $result = $this->app?->make(CrossMemberTransaction::class)->run(static function () use (&$attempts, $second): string {

                    $attempts++;

                    return self::remove($second->id);
                });

                return sprintf('%s at attempt %d: %s', $result, $attempts, implode(' ', $refusals->getArrayCopy()));
            },
            $level,
        );

        $refusal = 'laravel-authentication refused the change [mfa.remove_factor] from the session: [step_up_required].';

        self::assertSame(sprintf('not_fresh at attempt %d: %s', self::canGoOnAgainstTheOtherSide($level) ? 1 : 2, $refusal), $outcome);
        self::assertNull(Factor::query()->find($first->id));
        self::assertNotNull(Factor::query()->find($second->id));
    }

    /**
     * Rows of `[neighbouring proof, how it is made, what it reports]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideNeighbouringProofs(): iterable
    {
        $directly = QueryException::class . ', a concurrency failure';
        $nested   = DeadlockException::class . ', a concurrency failure';
        $retried  = 'session_revoked at attempt 2';

        foreach ([self::STEP_UP => 'a step-up of the later session', self::REAUTHENTICATION => 'a reauthentication of the earlier session'] as $proof => $name) {

            yield $name . ', made directly' => [$proof, self::DIRECTLY, $directly];

            yield $name . ', inside the caller\'s transaction' => [$proof, self::IN_A_TRANSACTION, $nested];

            yield $name . ', inside Iam::transaction()' => [$proof, self::IN_IAM_TRANSACTION, $retried];
        }
    }

    /**
     * A neighbouring proof deadlocked with a removal is a concurrency failure.
     *
     * @param  string  $proof
     * @param  string  $how
     * @param  string  $reported
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideNeighbouringProofs')]
    public function testANeighbouringProofDeadlockedWithARemovalFailsAsAConcurrencyFailure(string $proof, string $how, string $reported): void
    {
        $this->needsADeadlock();

        [$person, $sessions]   = $this->arrange(2);
        [$current, $neighbour] = $proof === self::STEP_UP ? $sessions : array_reverse($sessions);
        [$removed, $kept]      = $this->factorsOf($person);
        $neighbouring          = SessionProof::query()->where('session_id', $neighbour->getKey());
        $proofs                = $neighbouring->count();

        $this->actingOnSession($current);
        $this->stepUpWith($person, $current, $kept->id);

        $key = $this->signInReference($neighbour);

        [$removal, $neighbours] = $this->deadlock(
            static fn (): string => self::remove($removed->id),
            fn (): string => $this->proveOnNeighbour($proof, $person, $key, $kept->id, $how),
        );

        self::assertSame(self::ALLOWED, $removal);
        self::assertSame($reported, $neighbours);
        self::assertNull(Factor::query()->find($removed->id));
        self::assertNull($this->firstFactorOf($neighbour));
        self::assertSame($proofs, $neighbouring->count());
        self::assertSame(SessionStatus::ACTIVE, Session::query()->findOrFail($this->signInReference($current))->getStatus());
    }

    /**
     * Rows of `[path, isolation level]`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideChangesAtIsolationLevels(): iterable
    {
        foreach (['a step-up with an authenticator app', 'a step-up with a delivered code', 'a removal', 'an enrolment'] as $path) {
            foreach (self::provideIsolationLevels() as $name => [$level]) {
                yield $path . ' at ' . $name => [$path, $level];
            }
        }
    }

    /**
     * Each change locks the identity's state and factors before the session.
     *
     * @param  string  $path
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesAtIsolationLevels')]
    public function testEachChangeTakesTheIdentityStateAndFactorsBeforeTheSessionRow(string $path, string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, [$session]] = $this->arrange(1);
        [$removed, $kept]     = $this->factorsOf($person);

        $this->stepUpWith($person, $session, $kept->id);
        $this->travel(31)->seconds();

        [$change, $challenge, $sessionLast] = $this->changeOn($path, $person, $removed, $kept);

        $statements = $this->recordTransaction($change);

        self::assertLocksTheIdentityThenTheSession($statements);

        if ($challenge !== null) {

            $consumed = self::firstIndex($statements, $challenge);

            self::assertIsInt($consumed, implode("\n", $statements));
            self::assertGreaterThan(1, $consumed);
            self::assertLessThan(self::lastLockOf($statements, self::SESSIONS), $consumed);
        }

        $writes = array_values(array_filter($statements, static fn (string $sql): bool => self::isWrite($sql)));

        self::assertSame($sessionLast, str_starts_with((string) self::tableOf((string) end($writes)), 'authentication_'), implode("\n", $statements));
    }

    /**
     * A removal locks the current session before the identity's other sessions.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARemovalTakesTheCurrentSessionAndItsProofsBeforeTheIdentitysOtherSessions(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, [$current, $other]] = $this->arrange(2);
        [$removed, $kept]             = $this->factorsOf($person);

        $this->stepUpWith($person, $current, $kept->id);

        $statements = $this->recordTransactionWithBindings(static fn (): bool => Mfa::removeFactor(self::servedCaller(), $removed->id)->wasMade());
        $listing    = implode("\n", array_map(static fn (array $statement): string => $statement['sql'] . ' [' . implode(', ', $statement['bindings']) . ']', $statements));

        $currentKey = $this->signInReference($current);
        $otherKey   = $this->signInReference($other);
        $session    = self::firstLockOfRow($statements, self::SESSIONS, $currentKey);
        $proofs     = self::firstReadOf($statements, self::PROOFS, $currentKey);
        $others     = self::firstLockOfRow($statements, self::SESSIONS, $otherKey);

        self::assertIsInt($session, $listing);
        self::assertIsInt($proofs, $listing);
        self::assertIsInt($others, $listing);
        self::assertLessThan($proofs, $session, $listing);
        self::assertLessThan($others, $proofs, $listing);
        self::assertSame('factor_removed', Session::query()->findOrFail($otherKey)->getRevokedReason());
    }

    /**
     * Give the worker and the observer connections of their own.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = $app->make(Repository::class);

        $config->set('database.connections.' . self::RACER, $config->get('database.connections.' . self::CONNECTION));
        $config->set('database.connections.' . self::OBSERVER, $config->get('database.connections.' . self::CONNECTION));
    }

    /**
     * A person signed in as many times as asked.
     *
     * @param  int  $sessions
     * @return array{0: \Tests\Fixtures\Models\Person, 1: list<\SineMacula\Laravel\Authentication\Models\Session>}
     *
     * @throws \Throwable
     */
    private function arrange(int $sessions): array
    {
        $person = $this->createPerson();
        $signed = [];

        for ($session = 0; $session < $sessions; $session++) {

            $record = $this->signIn($person)->record;

            self::assertInstanceOf(Session::class, $record);

            $signed[] = $record;
        }

        $this->actingOnSession($signed[0]);

        return [$person, $signed];
    }

    /**
     * Two confirmed factors of the person's: one to remove and one to keep.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return array{0: \SineMacula\Laravel\Mfa\Models\Factor, 1: \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function factorsOf(Person $person): array
    {
        return [$this->confirmedFactor($person), $this->confirmedFactor($person)];
    }

    /**
     * Remove the factor from the session the key names, reporting the outcome.
     *
     * @param  string  $key
     * @param  string  $factor
     * @return string
     *
     * @throws \Throwable
     */
    private function removeOn(string $key, string $factor): string
    {
        $this->actingOnSession(Session::query()->findOrFail($key));

        return self::remove($factor);
    }

    /**
     * Remove the factor from the guard's session, reporting the outcome.
     *
     * @param  string  $factor
     * @return string
     *
     * @throws \Throwable
     */
    private static function remove(string $factor): string
    {
        $result = Mfa::removeFactor(self::servedCaller(), $factor);

        return $result->wasMade() ? self::ALLOWED : (string) $result->reason?->value;
    }

    /**
     * Remove the factor, retrying once when it fails to serialise.
     *
     * @param  string  $key
     * @param  string  $factor
     * @return string
     *
     * @throws \Throwable
     */
    private function removeRetryingTheRequest(string $key, string $factor): string
    {
        try {
            return sprintf('%s at attempt 1', $this->removeOn($key, $factor));
        } catch (\Throwable $exception) {

            if (self::failureOf($exception) !== self::SERIALISATION_FAILURE) {
                throw $exception;
            }
        }

        return sprintf('%s at attempt 2', $this->removeOn($key, $factor));
    }

    /**
     * Step up or reauthenticate the session as asked, reporting the outcome.
     *
     * @param  string  $proof
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $key
     * @param  string  $factor
     * @param  string  $how
     * @return string
     */
    private function proveOnNeighbour(string $proof, Person $person, string $key, string $factor, string $how): string
    {
        $attempts = 0;

        $prove = function () use (&$attempts, $proof, $person, $key, $factor): string {

            $attempts++;

            $session = Session::query()->findOrFail($key);
            $result  = $proof === self::STEP_UP
                ? $this->stepUp($person, $session, $factor)
                : $this->sessions()->reauthenticate($session, 'password', ['email' => $person->email, 'password' => self::PASSWORD], self::client());

            return $result->reason->value ?? self::ALLOWED;
        };

        try {
            return match ($how) {
                self::DIRECTLY         => $prove(),
                self::IN_A_TRANSACTION => self::storage()->transaction($prove),
                default                => sprintf('%s at attempt %d', $this->app?->make(CrossMemberTransaction::class)->run($prove), $attempts),
            };
        } catch (\Throwable $exception) {
            return self::concurrencyFailureOf($exception);
        }
    }

    /**
     * Have the bound gate run the callback once it allows a change.
     *
     * @param  \Closure(): void  $then
     * @return void
     */
    private function holdAfterTheGate(\Closure $then): void
    {
        $this->app?->extend(FactorChangeGate::class, static fn (FactorChangeGate $gate): FactorChangeGate => new readonly class ($gate, $then) implements FactorChangeGate {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\FactorChangeGate  $gate
             * @param  \Closure(): void  $then
             */
            public function __construct(

                /** The gate every change is passed on to. */
                private FactorChangeGate $gate,

                /** What runs once the gate allows a change. */
                private \Closure $then,
            ) {}

            /**
             * Pass the change on, and run the callback once it is allowed.
             *
             * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
             * @return ?\Carbon\CarbonImmutable
             *
             * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
             */
            #[\Override]
            public function authorize(FactorChangeRequest $request): ?CarbonImmutable
            {
                $freshUntil = $this->gate->authorize($request);

                ($this->then)();

                return $freshUntil;
            }
        });
    }

    /**
     * Record every refusal the bound factor-change gate throws.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordGateRefusals(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $refusals */
        $refusals = new \ArrayObject;

        $this->app?->extend(FactorChangeGate::class, static fn (FactorChangeGate $gate): FactorChangeGate => new readonly class ($gate, $refusals) implements FactorChangeGate {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\FactorChangeGate  $gate
             * @param  \ArrayObject<int, string>  $refusals
             */
            public function __construct(

                /** The gate every change is passed on to. */
                private FactorChangeGate $gate,

                /** The detail of every refusal, in order. */
                private \ArrayObject $refusals,
            ) {}

            /**
             * Pass the change on, recording the detail of a refusal.
             *
             * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
             * @return ?\Carbon\CarbonImmutable
             *
             * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
             */
            #[\Override]
            public function authorize(FactorChangeRequest $request): ?CarbonImmutable
            {
                try {
                    return $this->gate->authorize($request);
                } catch (OperationRefusedException $refusal) {
                    $this->refusals->append($refusal->getMessage());

                    throw $refusal;
                }
            }
        });

        return $refusals;
    }

    /**
     * Assert what a removal raced against a step-up kept.
     *
     * @param  bool  $made
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $current
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $other
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $removed
     * @return void
     */
    private function assertRemovalKept(bool $made, Session $current, Session $other, Factor $removed): void
    {
        self::assertSame($made, Factor::query()->find($removed->id) === null);
        self::assertSame($made, $this->firstFactorOf($other) === null);
        self::assertSame(SessionStatus::ACTIVE, Session::query()->findOrFail($this->signInReference($current))->getStatus());
        self::assertSame(
            [ProofKind::ADDITIONAL_FACTOR, ProofKind::FIRST_FACTOR],
            array_map(static fn (RecordedProof $proof): ProofKind => $proof->kind, $this->proofsOf($current)),
        );
    }

    /**
     * Have `laravel-authentication` ask for a phishing-resistant proof.
     *
     * @return void
     */
    private function requirePhishingResistance(): void
    {
        $this->app?->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Ask for phishing resistance of any age.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return new Requirement(phishingResistance: new RequirementPart);
            }
        });
    }

    /**
     * The change the path names, ready to run.
     *
     * @param  string  $path
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $removed
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $kept
     * @return array{0: \Closure(): bool, 1: ?string, 2: bool}
     *
     * @throws \Throwable
     */
    private function changeOn(string $path, Person $person, Factor $removed, Factor $kept): array
    {
        $enrol = static fn (): bool => Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::totp(self::DESTINATION))->reason === null;

        return match ($path) {
            'a step-up with an authenticator app' => [
                static fn (): bool => Mfa::verify(self::servedCaller(), Submission::factor($kept->id, AuthenticatorApp::code($kept)), Purpose::STEP_UP)->isVerified(),
                'last_accepted_step',
                true,
            ],
            'a step-up with a delivered code' => [$this->deliveredCodeStepUp($person), 'update ' . self::quoted('mfa_codes') . ' set ' . self::quoted('consumed_at'), true],
            'a removal'                       => [static fn (): bool => Mfa::removeFactor(self::servedCaller(), $removed->id)->wasMade(), null, true],
            default                           => [$enrol, null, false],
        };
    }

    /**
     * A step-up with an email code sent by MFA's own challenge gateway.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \Closure(): bool
     *
     * @throws \Throwable
     */
    private function deliveredCodeStepUp(Person $person): \Closure
    {
        config()->set('mfa.applications.' . self::GUARD . '.types', ['totp', 'email']);

        $this->app?->bind(ChallengeGateway::class, PackageChallengeGateway::class);

        $sender = FakeEmailSender::fake($this->app);
        $factor = Factor::query()->create([
            'type'                 => 'email',
            'destination'          => self::DESTINATION,
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => ProofOwner::of($person)->key,
            'status'               => FactorStatus::CONFIRMED->value,
            'application'          => self::GUARD,
            'confirmed_at'         => now(),
        ]);

        $sent = Mfa::sendCode(self::servedCaller(), $factor->id, Purpose::STEP_UP);
        $code = $sender->lastCodeTo(self::DESTINATION);

        self::assertNull($sent->reason);
        self::assertIsString($sent->challengeId);
        self::assertIsString($code);

        $challenge = $sent->challengeId;

        return static fn (): bool => Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, $challenge, $code), Purpose::STEP_UP)->isVerified();
    }

    /**
     * Run the change and return its one transaction's statements.
     *
     * @param  \Closure(): bool  $change
     * @return list<string>
     *
     * @throws \Throwable
     */
    private function recordTransaction(\Closure $change): array
    {
        $this->listenToTheStorageConnection();

        $this->recording = true;

        try {
            self::assertTrue($change(), 'The change did not go ahead.');
        } finally {
            $this->recording = false;
        }

        self::assertSame(1, $this->outermost, 'The change did not run in exactly one transaction.');

        $inside = array_filter($this->statements, static fn (array $statement): bool => $statement['level'] > 0);

        return array_values(array_map(static fn (array $statement): string => $statement['sql'], $inside));
    }

    /**
     * Run the change and return its statements with their bindings.
     *
     * @param  \Closure(): bool  $change
     * @return list<array{sql: string, bindings: list<string>}>
     *
     * @throws \Throwable
     */
    private function recordTransactionWithBindings(\Closure $change): array
    {
        $this->recordTransaction($change);

        $inside = array_filter($this->statements, static fn (array $statement): bool => $statement['level'] > 0);

        return array_values(array_map(static fn (array $statement): array => ['sql' => $statement['sql'], 'bindings' => $statement['bindings']], $inside));
    }

    /**
     * The index of the first statement that locks the table's row, if any.
     *
     * @param  list<array{sql: string, bindings: list<string>}>  $statements
     * @param  string  $table
     * @param  string  $key
     * @return ?int
     */
    private static function firstLockOfRow(array $statements, string $table, string $key): ?int
    {
        foreach ($statements as $index => $statement) {
            if (self::isLock($statement['sql']) && self::tableOf($statement['sql']) === $table && in_array($key, $statement['bindings'], true)) {
                return $index;
            }
        }

        return null;
    }

    /**
     * The index of the first statement that reads the table's rows, if any.
     *
     * @param  list<array{sql: string, bindings: list<string>}>  $statements
     * @param  string  $table
     * @param  string  $key
     * @return ?int
     */
    private static function firstReadOf(array $statements, string $table, string $key): ?int
    {
        foreach ($statements as $index => $statement) {
            if (str_starts_with($statement['sql'], 'select ') && self::tableOf($statement['sql']) === $table && in_array($key, $statement['bindings'], true)) {
                return $index;
            }
        }

        return null;
    }

    /**
     * Record the storage connection's statements and outermost transactions.
     *
     * @return void
     */
    private function listenToTheStorageConnection(): void
    {
        $storage = self::storage()->getName();

        DB::listen(function (QueryExecuted $query) use ($storage): void {

            if (!$this->recording || $query->connectionName !== $storage) {
                return;
            }

            $bindings = array_map(static fn (mixed $binding): string => is_scalar($binding) ? (string) $binding : get_debug_type($binding), $query->bindings);

            $this->statements[] = ['level' => $this->level, 'sql' => preg_replace('/\s+/', ' ', $query->sql) ?? $query->sql, 'bindings' => array_values($bindings)];
        });

        Event::listen([TransactionBeginning::class, TransactionCommitted::class, TransactionRolledBack::class], function (ConnectionEvent $event) use ($storage): void {

            if (!$this->recording || $event->connectionName !== $storage) {
                return;
            }

            $this->countTransaction($event);
        });
    }

    /**
     * Track the storage connection's transaction level.
     *
     * @param  \Illuminate\Database\Events\ConnectionEvent  $event
     * @return void
     */
    private function countTransaction(ConnectionEvent $event): void
    {
        $begins = $event instanceof TransactionBeginning;

        $this->outermost += $begins && $this->level === 0 ? 1 : 0;
        $this->level     += $begins ? 1 : -1;
    }

    /**
     * Assert the identity's state and factors are locked before the session.
     *
     * @param  list<string>  $statements
     * @return void
     */
    private static function assertLocksTheIdentityThenTheSession(array $statements): void
    {
        $listing = implode("\n", $statements);
        $tables  = array_values(array_filter(
            array_map(static fn (string $sql): ?string => self::isLock($sql) ? self::tableOf($sql) : null, $statements),
            static fn (?string $table): bool => $table !== null,
        ));

        self::assertSame([self::IDENTITY_STATE, self::FACTORS], array_slice($tables, 0, 2), $listing);
        self::assertSame(self::IDENTITY_STATE, self::tableOf($statements[0]), $listing);
        self::assertGreaterThan(1, array_search(self::SESSIONS, $tables, true), $listing);

        foreach ($tables as $table) {
            if (!str_starts_with($table, 'mfa_')) {
                continue;
            }

            self::assertContains($table, self::IDENTITY_TABLES, $listing);
        }
    }

    /**
     * The index of the first statement that holds the text, if any.
     *
     * @param  list<string>  $statements
     * @param  string  $text
     * @return ?int
     */
    private static function firstIndex(array $statements, string $text): ?int
    {
        foreach ($statements as $index => $sql) {
            if (str_contains($sql, $text)) {
                return $index;
            }
        }

        return null;
    }

    /**
     * The index of the last statement that locks or writes a row of the table.
     *
     * @param  list<string>  $statements
     * @param  string  $table
     * @return int
     */
    private static function lastLockOf(array $statements, string $table): int
    {
        $last = -1;

        foreach ($statements as $index => $sql) {
            if (!self::isLock($sql) || self::tableOf($sql) !== $table) {
                continue;
            }

            $last = $index;
        }

        return $last;
    }

    /**
     * Whether the statement locks or writes a row.
     *
     * @param  string  $sql
     * @return bool
     */
    private static function isLock(string $sql): bool
    {
        return self::isWrite($sql) || preg_match('/ for (update|share|no key update)$| lock in share mode$/i', $sql) === 1;
    }

    /**
     * Whether the statement writes: an insert, an update or a delete.
     *
     * @param  string  $sql
     * @return bool
     */
    private static function isWrite(string $sql): bool
    {
        return preg_match('/^(insert|update|delete)\b/i', $sql) === 1;
    }

    /**
     * The table the statement reads, writes or locks first.
     *
     * @param  string  $sql
     * @return ?string
     */
    private static function tableOf(string $sql): ?string
    {
        return preg_match('/\b(?:from|into|update)\s+[`"]?(\w+)[`"]?/i', $sql, $match) === 1 ? $match[1] : null;
    }

    /**
     * The identifier as the storage connection's grammar quotes it.
     *
     * @param  string  $identifier
     * @return string
     */
    private static function quoted(string $identifier): string
    {
        return self::storage()->getQueryGrammar()->wrap($identifier);
    }

    /**
     * Skip on SQLite or without fork support, else set the isolation level.
     *
     * @param  string  $level
     * @return void
     */
    private function needsARace(string $level): void
    {
        self::requireIsolationLevels();

        if (!function_exists('pcntl_fork') || !function_exists('posix_kill')) {
            self::markTestSkipped('A race needs a process that can fork.');
        }

        self::useIsolationLevel($level);
    }

    /**
     * Race the first side against a forked worker, returning its report.
     *
     * @param  \Closure(): mixed  $first
     * @param  \Closure(): string  $second
     * @param  string  $level
     * @return string
     *
     * @throws \Throwable
     */
    private function race(\Closure $first, \Closure $second, string $level): string
    {
        $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

        self::assertIsArray($sockets);

        [$parent, $worker] = $sockets;

        $send = static function (string $line) use ($worker): void {
            fwrite($worker, $line . "\n");
        };

        $receive = static function () use ($parent): string {

            stream_set_timeout($parent, self::WORKER_TIMEOUT);

            $line = fgets($parent);

            self::assertIsString($line, 'The worker sent nothing.');

            return trim($line);
        };

        $connection = self::storage();

        $connection->beginTransaction();

        $first();

        $pid = pcntl_fork();

        if ($pid === 0) {
            fclose($parent);
            $this->runInWorker($second, $send, $level);
        }

        fclose($worker);

        try {
            self::assertGreaterThan(0, $pid, 'The worker could not be forked.');

            $this->awaitLockWait($receive());

            $connection->commit();

            return $receive();
        } finally {
            if ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }

            if ($pid > 0) {
                pcntl_waitpid($pid, $status);
            }
        }
    }

    /**
     * Skip unless on MySQL or MariaDB with fork support.
     *
     * @return void
     */
    private function needsADeadlock(): void
    {
        if (!in_array(DB::connection()->getDriverName(), ['mysql', 'mariadb'], true)) {
            self::markTestSkipped('Only MySQL and MariaDB lock the gaps a current read spans.');
        }

        $this->needsARace('repeatable read');
    }

    /**
     * Deadlock the first side with a forked worker, returning both reports.
     *
     * @param  \Closure(): string  $first
     * @param  \Closure(): string  $second
     * @return array{0: string, 1: string}
     *
     * @throws \Throwable
     */
    private function deadlock(\Closure $first, \Closure $second): array
    {
        $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

        self::assertIsArray($sockets);

        [$parent, $worker] = $sockets;

        $pid = pcntl_fork();

        if ($pid === 0) {
            fclose($parent);

            $this->runInWorker(static function () use ($worker, $second): string {

                stream_set_timeout($worker, self::WORKER_TIMEOUT);

                return trim((string) fgets($worker)) === self::GO ? $second() : 'The worker was never told to go on.';
            }, static function (string $line) use ($worker): void {
                fwrite($worker, $line . "\n");
            }, 'repeatable read');
        }

        fclose($worker);

        $receive = static function () use ($parent): string {

            stream_set_timeout($parent, self::WORKER_TIMEOUT);

            $line = fgets($parent);

            self::assertIsString($line, 'The worker sent nothing.');

            return trim($line);
        };

        try {
            self::assertGreaterThan(0, $pid, 'The worker could not be forked.');

            $backend = $receive();

            $this->holdAfterTheGate(function () use ($parent, $backend): void {
                fwrite($parent, self::GO . "\n");
                $this->awaitLockWait($backend);
            });

            try {
                $outcome = $first();
            } catch (\Throwable $exception) {
                $outcome = self::concurrencyFailureOf($exception);
            }

            return [$outcome, $receive()];
        } finally {
            if ($pid > 0) {
                pcntl_waitpid($pid, $status);
            }
        }
    }

    /**
     * Run the second side in the forked worker, then kill the worker.
     *
     * @param  \Closure(): string  $second
     * @param  \Closure(string): void  $send
     * @param  string  $level
     * @return never
     */
    private function runInWorker(\Closure $second, \Closure $send, string $level): never
    {
        try {
            DB::setDefaultConnection(self::RACER);

            self::useIsolationLevel($level, self::RACER);

            $connection = DB::connection(self::RACER);
            $backend    = $connection->scalar($connection->getDriverName() === 'pgsql' ? 'select pg_backend_pid()' : 'select connection_id()');

            $send(is_scalar($backend) ? (string) $backend : '');

            $outcome = $second();
        } catch (\Throwable $exception) {
            $outcome = self::failureOf($exception);
        }

        $send($outcome);

        posix_kill((int) getmypid(), SIGKILL);

        exit(1);
    }

    /**
     * Wait until the database reports the worker waiting on a row lock.
     *
     * @param  string  $backend
     * @return void
     */
    private function awaitLockWait(string $backend): void
    {
        $observer = DB::connection(self::OBSERVER);

        $query = $observer->getDriverName() === 'pgsql'
            ? 'select count(*) from pg_stat_activity where pid = ? and wait_event_type = \'Lock\''
            : 'select count(*) from information_schema.innodb_trx where trx_mysql_thread_id = ? and trx_state = \'LOCK WAIT\'';

        for ($poll = 0; $poll < self::POLLS; $poll++) {

            $waiting = $observer->scalar($query, [(int) $backend], false);

            if (is_numeric($waiting) && (int) $waiting > 0) {
                return;
            }

            usleep(self::POLL_INTERVAL);
        }

        self::fail(sprintf('The worker never waited on a lock; it reported [%s].', $backend));
    }

    /**
     * What the worker reports for a failure.
     *
     * @param  \Throwable  $exception
     * @return string
     */
    private static function failureOf(\Throwable $exception): string
    {
        for ($failure = $exception; $failure !== null; $failure = $failure->getPrevious()) {
            if ((string) $failure->getCode() === self::SERIALISATION_STATE) {
                return self::SERIALISATION_FAILURE;
            }
        }

        return sprintf('%s: %s', $exception::class, str_replace("\n", ' ', $exception->getMessage()));
    }

    /**
     * What a side reports for a failure, as a concurrency failure or not.
     *
     * @param  \Throwable  $exception
     * @return string
     */
    private static function concurrencyFailureOf(\Throwable $exception): string
    {
        if (!(new ConcurrencyErrorDetector)->causedByConcurrencyError($exception)) {
            return sprintf('%s: %s', $exception::class, str_replace("\n", ' ', $exception->getMessage()));
        }

        return $exception::class . ', a concurrency failure';
    }

    /**
     * Whether a waiting transaction can go on against the other's commit.
     *
     * @param  string  $level
     * @return bool
     */
    private static function canGoOnAgainstTheOtherSide(string $level): bool
    {
        return DB::connection()->getDriverName() !== 'pgsql' || $level !== 'repeatable read';
    }
}
