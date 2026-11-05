<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
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
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
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
 * Races MFA's factor changes, gated and revoked through
 * `laravel-authentication` (IAM-3.6, IAM-3.7), against a step-up of the same
 * session and against each other, on MySQL and PostgreSQL at READ COMMITTED and
 * REPEATABLE READ, with every adapter between the two members bound by this
 * package's binding rule, as an application gets them.
 *
 * Every MFA change takes the identity's state first and its factors second, in
 * one transaction on the storage connection, before any row of
 * `laravel-authentication`'s; the session's row is taken after both, and any
 * other row of MFA's taken after it (a challenge, an enrolment, a passkey
 * association) is one of the identity's own, which no transaction takes without
 * the identity's state. `laravel-authentication` alone takes the session's row
 * and nothing of MFA's. A removal goes on to take the identity's other
 * sessions' rows after the current session's row and its proofs, in the
 * revoker's `factorRemoved()`. So, but for the one deadlock below, no two
 * transactions can each hold a row the other waits on: whichever holds the
 * contended row first commits, and the other resumes against what it committed,
 * never deadlocked and never against what it overwrote. A PostgreSQL
 * transaction at REPEATABLE READ that cannot see what the other committed fails
 * to serialise instead; MFA opens its own transaction, which never retries and
 * is not to be wrapped, so the caller retries the request (IAM-11.2). One
 * wrapped all the same never goes ahead on a step-up voided while it waited:
 * `laravel-authentication`'s gate judges the session's proofs as committed
 * under the session's lock, whatever the wrapping transaction read first, and
 * refuses it itself.
 *
 * The one deadlock left is `laravel-authentication`'s by design: on MySQL at
 * REPEATABLE READ a removal's freshness judgement holds the gaps around the
 * session's proofs, and a step-up or reauthentication of the identity's
 * neighbouring session, holding that session's row while its proof waits on a
 * gap, deadlocks with the removal that goes on to end it. The database fails
 * the neighbour's side, with nothing of it written, as a concurrency failure
 * whose class depends on whether a transaction was already open around it.
 *
 * The second side of each race runs in a forked worker on a connection of its
 * own, which the test never opened, so the two share none; the test commits its
 * side only once the database reports the worker waiting on a lock.
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
     * A step-up of the session that waits on a removal holding its row resumes
     * once the removal commits, and is refused: the removal returned the
     * session to pending. At REPEATABLE READ on PostgreSQL the step-up cannot
     * see the removal, so it fails to serialise instead.
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
            static fn (): bool => Mfa::removeFactor($removed->id)->wasMade(),
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
     * A removal that waits on a step-up holding the session's row resumes once
     * the step-up commits, and is allowed on it. At REPEATABLE READ on
     * PostgreSQL the removal cannot see the step-up, so it fails to serialise
     * instead, and nothing of it is kept: MFA's own transaction never retries.
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
     * A factor change (enrolling a further factor, gated through
     * `laravel-authentication`) that waits on a removal holding the identity's
     * state resumes once the removal commits, against the factors it left, and
     * is allowed on the step-up the session still holds. At REPEATABLE READ on
     * PostgreSQL it cannot see the removal, so it fails to serialise instead.
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
            static fn (): bool => Mfa::removeFactor($removed->id)->wasMade(),
            function () use ($key): string {

                $this->actingOnSession(Session::query()->findOrFail($key));

                return Mfa::startEnrollment(EnrollmentRequest::totp(self::DESTINATION))->reason->value ?? self::ALLOWED;
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
     * A removal that waits on a step-up and fails to serialise is made when the
     * caller retries the request, as MFA's changes are retried (IAM-11.2): MFA
     * opens its own transaction, which never retries and cannot be wrapped, so
     * the failure reaches the caller, and the request made again is allowed on
     * the step-up it waited on. Only PostgreSQL at REPEATABLE READ fails; at
     * every other level the first request is allowed.
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
     * MFA's changes are not to be run inside a transaction someone else opens,
     * `Iam::transaction()` included (IAM-11.2), and one that is never goes
     * ahead on a step-up voided while it waited. The session holds step-ups
     * made with two factors; one removal, allowed on the step-up with the
     * second, voids the step-up with the first, while a removal of the second,
     * run inside `Iam::transaction()`, waits on it. Once the first commits, the
     * second has only the voided step-up left, and is refused as not fresh at
     * every level, by `laravel-authentication`'s own gate (`step_up_required`),
     * the refusal this package's gate passes on as it is: at REPEATABLE READ on
     * MySQL the snapshot fixed before the wait still shows the voided step-up
     * to a plain read, but the gate judges the session's proofs as committed
     * under the session's lock; on PostgreSQL the first attempt fails to
     * serialise and the package's transaction runs it again.
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
     * Rows of `[the neighbouring session's proof, how it is made, what it
     * reports]`: a step-up of the session signed in after the removal's, or a
     * reauthentication of the one signed in before it, each made directly
     * through `laravel-authentication`, its own transaction the outermost;
     * inside a transaction the caller opened; and inside `Iam::transaction()`,
     * which retries it whole.
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
     * On MySQL at REPEATABLE READ a removal's freshness judgement holds the
     * gaps on either side of the session's proofs until MFA's transaction ends.
     * A step-up or a reauthentication of the identity's neighbouring session,
     * whose proofs border these, holds that session's row while its proof waits
     * on a gap, and the removal, ending the neighbouring session, then waits on
     * its row. The database fails one side, the neighbour's, with nothing of it
     * written, and the removal goes ahead. The failure is Laravel's
     * `DeadlockException` only when the neighbour's side ran inside a
     * transaction the caller opened; made directly, its own transaction the
     * outermost, it is the `QueryException` the database raised, which
     * Laravel's concurrency detection recognises all the same. Inside
     * `Iam::transaction()`, it is retried whole, against the removal, which
     * ended the session.
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
     * Rows of `[path, isolation level]`: each change MFA makes through the
     * adapters at each level.
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
     * Each change takes the identity's state first and its factors second, in
     * one transaction, before any row of `laravel-authentication`'s; the
     * challenge a step-up proves is consumed under them; the session's row is
     * taken after both; and every row of MFA's taken after the session's is the
     * identity's own, which no transaction takes without the identity's state.
     * A step-up and a removal write the session last; MFA's counters of
     * attempts are kept outside the transaction.
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
     * A removal takes the current session's row, then reads its proofs, and
     * only then, in the revoker's `factorRemoved()`, takes the row of the
     * identity's other session, which it ends: `laravel-authentication`'s
     * order, under which another session's row is taken after the current
     * session's, never before it. That order is what leaves the deadlock with a
     * neighbouring session's proof on MySQL at REPEATABLE READ.
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

        $statements = $this->recordTransactionWithBindings(static fn (): bool => Mfa::removeFactor($removed->id)->wasMade());
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
     * Give the worker and the observer connections of their own to the test's
     * database.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(Repository::class);

        $config->set('database.connections.' . self::RACER, $config->get('database.connections.' . self::CONNECTION));
        $config->set('database.connections.' . self::OBSERVER, $config->get('database.connections.' . self::CONNECTION));
    }

    /**
     * A person signed in as many times as asked, the guard acting on the first
     * session. Each test gives the person their factors only afterwards, so
     * MFA's requirement asks none of the sessions for a further factor.
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
     * Remove the factor through MFA from the session the key names, reporting
     * whether the removal was made, or MFA's reason when it was not.
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
     * Remove the factor through MFA from the session the guard acts on,
     * reporting whether the removal was made, or MFA's reason when it was not.
     *
     * @param  string  $factor
     * @return string
     *
     * @throws \Throwable
     */
    private static function remove(string $factor): string
    {
        $result = Mfa::removeFactor($factor);

        return $result->wasMade() ? self::ALLOWED : (string) $result->reason?->value;
    }

    /**
     * Remove the factor through MFA from the session the key names, as a
     * request would, and make the request once more when it fails to serialise,
     * reporting the outcome and the attempt that reached it.
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
     * Step the session the key names up with the factor, or reauthenticate it
     * with the person's password, made as asked: directly, inside a transaction
     * opened on the storage connection, or inside `Iam::transaction()`. Reports
     * whether it was issued, or the reason it was not, with the attempt that
     * reached it inside `Iam::transaction()`; or the failure it threw and
     * whether Laravel's concurrency detection recognises it.
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
                : $this->sessions()->reauthenticate($session, 'password', ['email' => $person->email, 'password' => self::PASSWORD]);

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
     * Have the bound factor-change gate, once it allows a change, run the
     * callback before it hands the change back to MFA, inside MFA's
     * transaction.
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
     * Record, from now on, the detail of every refusal the bound factor-change
     * gate throws, passing each on unchanged, and return the record.
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
     * Assert what a removal raced against a step-up kept: when made, the factor
     * gone, every other session ended and the current session's step-up with
     * the kept factor still counting; when not, nothing of it.
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
     * From now on, have `laravel-authentication` ask every session for a
     * phishing-resistant proof, which no authenticator app code is, so a
     * session judged again after a removal returns to pending.
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
     * The change the path names, ready to run, with the statement that consumes
     * its challenge (when it proves one) and whether it writes the session
     * last.
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
        return match ($path) {
            'a step-up with an authenticator app' => [
                static fn (): bool => Mfa::verify(Submission::factor($kept->id, AuthenticatorApp::code($kept)), Purpose::STEP_UP)->isVerified(),
                'last_accepted_step',
                true,
            ],
            'a step-up with a delivered code' => [$this->deliveredCodeStepUp($person), 'update ' . self::quoted('mfa_codes') . ' set ' . self::quoted('consumed_at'), true],
            'a removal'                       => [static fn (): bool => Mfa::removeFactor($removed->id)->wasMade(), null, true],
            default                           => [static fn (): bool => Mfa::startEnrollment(EnrollmentRequest::totp(self::DESTINATION))->reason === null, null, false],
        };
    }

    /**
     * A step-up with a code delivered to an email factor of the person's, sent
     * now, ready to verify.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \Closure(): bool
     *
     * @throws \Throwable
     */
    private function deliveredCodeStepUp(Person $person): \Closure
    {
        config()->set('mfa.applications.' . self::GUARD . '.types', ['totp', 'email']);

        $sender = FakeEmailSender::fake($this->app);
        $factor = Factor::query()->create([
            'type'                 => 'email',
            'destination'          => self::DESTINATION,
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => IdentityReference::of($person)->key,
            'status'               => FactorStatus::CONFIRMED->value,
            'application'          => self::GUARD,
            'confirmed_at'         => now(),
        ]);

        $sent = Mfa::sendCode($factor->id, Purpose::STEP_UP);
        $code = $sender->lastCodeTo(self::DESTINATION);

        self::assertNull($sent->reason);
        self::assertIsString($sent->challengeId);
        self::assertIsString($code);

        $challenge = $sent->challengeId;

        return static fn (): bool => Mfa::verify(Submission::challenge($factor->id, $challenge, $code), Purpose::STEP_UP)->isVerified();
    }

    /**
     * Run the change, failing unless it went ahead, and return the statements
     * it made inside its outermost transaction on the storage connection,
     * failing unless it made them in exactly one.
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
     * Run the change, failing unless it went ahead in exactly one transaction,
     * and return the statements it made inside it with their bindings.
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
     * The index of the first statement that locks or writes a row of the table
     * bound to the key given, or `null` when none does.
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
     * The index of the first statement that reads rows of the table bound to
     * the key given, or `null` when none does.
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
     * Record, while recording is on, every statement the storage connection
     * runs with the transaction level it runs at, and count the outermost
     * transactions it begins.
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
     * Follow the storage connection's transaction level through one of its
     * transaction events, counting an outermost transaction it begins.
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
     * Assert the transaction takes the identity's state first and its factors
     * second, touches no row of `laravel-authentication`'s before both, takes
     * the session's row after them, and takes no row of MFA's that is not the
     * identity's own: no counter of attempts, which MFA keeps outside it.
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
     * The index of the first statement that holds the text, or `null` when none
     * does.
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
     * Whether the statement locks or writes a row: a locking read, an insert,
     * an update or a delete.
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
     * Skip the race where it cannot be run: on SQLite, or a process that cannot
     * fork; otherwise set the level of every transaction from now on.
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
     * Run the first side in a transaction left open, run the second in a forked
     * worker, commit once the database reports the worker waiting on a lock,
     * and return what the worker reported once it resumed.
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
     * Skip the deadlock where it cannot arise or cannot be run: anywhere but
     * MySQL and MariaDB, whose REPEATABLE READ locks the gaps a current read
     * spans, or in a process that cannot fork; otherwise run every transaction
     * from now on at REPEATABLE READ.
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
     * Fork a worker to run the second side, run the first, and once the first
     * is past the factor-change gate, still inside MFA's transaction, let the
     * worker go on and hold the first until the database reports the worker
     * waiting on a lock. Returns what each side reported, the first's failure
     * described as the worker's is.
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
     * Run the second side in the forked worker, on the racer's connection, as
     * the default and so the storage connection, at the level given. The worker
     * reports its connection's id before it starts and the outcome after, then
     * kills itself, so nothing the test set up is torn down twice.
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
     * Wait until the database reports the worker's connection waiting for a row
     * lock, failing when it never does.
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
     * What the worker reports for a failure: a failure to serialise, wherever
     * it is in the chain, or the failure itself.
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
     * What a side reports for a failure: its class, and whether Laravel's
     * concurrency detection recognises it as a deadlock or a failure to
     * serialise; or, when it does not, the failure itself.
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
     * Whether a transaction that waited on a row another committed a change to
     * can go on against that change: every one but PostgreSQL's at REPEATABLE
     * READ, which fails to serialise instead.
     *
     * @param  string  $level
     * @return bool
     */
    private static function canGoOnAgainstTheOtherSide(string $level): bool
    {
        return DB::connection()->getDriverName() !== 'pgsql' || $level !== 'repeatable read';
    }
}
