<?php

declare(strict_types = 1);

namespace Tests\Feature\Audit;

use Illuminate\Foundation\Testing\DatabaseTransactionsManager as TestingTransactionsManager;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Audit\DeferredRefusals;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthenticationEventMapper;
use SineMacula\Laravel\Iam\Transactions\ConnectionTransactions;
use Tests\TestCase;

/**
 * Feature tests for holding the refusals `laravel-authentication` reports while
 * a transaction is open on audit-log's storage connection until the outermost
 * transaction there has ended (IAM-9.5): a refusal reported while none is open
 * is recorded at once, and so is any other event reported inside one; a refusal
 * reported inside one is recorded once the outermost has committed, or once it,
 * or one enclosing it, has rolled back, in the order reported, once each; a
 * savepoint's end waits for the transaction enclosing it; a transaction on
 * another connection and the transaction a testing trait wraps a test in hold
 * nothing; and a refusal recorded is held no more. The refusals reach
 * audit-log's fake store through its whole capture pipeline, the authentication
 * mapper included.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeferredRefusals::class)]
#[CoversClass(ConnectionTransactions::class)]
#[CoversClass(AuthenticationEventMapper::class)]
final class DeferredRefusalsTest extends TestCase
{
    /** @var string The connection audit-log's storage is moved to, beside the default one. */
    private const string OTHER = 'audit';

    /** @var string The failure a transaction's work throws to roll it back. */
    private const string ROLLED_BACK = 'The transaction rolled back.';

    /** @var string The code a refused sign-in is recorded under. */
    private const string SIGN_IN_FAILED = 'authentication.sign_in_failed';

    /**
     * A refusal reported while no transaction is open is not held, and is
     * recorded at once.
     *
     * @return void
     */
    public function testARefusalReportedWithNoTransactionOpenIsRecordedAtOnce(): void
    {
        $fake = AuditLog::fake();

        self::assertFalse($this->refusals()->defers(self::refusal(FailureReason::INVALID_CREDENTIALS)));

        Event::dispatch(self::refusal(FailureReason::METHOD_NOT_ALLOWED));

        self::assertSame([[self::SIGN_IN_FAILED, 'method_not_allowed']], self::recorded($fake));
    }

    /**
     * A refusal reported inside a transaction is recorded only once it has
     * committed, once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalReportedInsideATransactionIsRecordedOnceItCommits(): void
    {
        $fake   = AuditLog::fake();
        $inside = [];

        $answer = DB::transaction(static function () use ($fake, &$inside): string {

            Event::dispatch(self::refusal(FailureReason::METHOD_NOT_ALLOWED));

            $inside = self::recorded($fake);

            return 'committed';
        });

        self::assertSame('committed', $answer);
        self::assertSame([], $inside);
        self::assertSame([[self::SIGN_IN_FAILED, 'method_not_allowed']], self::recorded($fake));
    }

    /**
     * The refusals reported inside a transaction that rolls back are recorded
     * once it has, in the order they were reported, and its failure still
     * reaches the caller.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRefusalsAreRecordedInOrderOnceTheTransactionRollsBack(): void
    {
        $fake    = AuditLog::fake();
        $inside  = null;
        $failure = self::thrownBy(static function () use ($fake, &$inside): never {

            DB::transaction(static function () use ($fake, &$inside): never {

                Event::dispatch(self::refusal(FailureReason::METHOD_NOT_ALLOWED));
                Event::dispatch(self::refusal(FailureReason::SSO_REQUIRED));

                $inside = self::recorded($fake);

                throw new \RuntimeException(self::ROLLED_BACK);
            });
        });

        self::assertSame(self::ROLLED_BACK, $failure->getMessage());
        self::assertSame([], $inside);
        self::assertSame(0, DB::transactionLevel());
        self::assertSame([
            [self::SIGN_IN_FAILED, 'method_not_allowed'],
            [self::SIGN_IN_FAILED, 'sso_required'],
        ], self::recorded($fake));
    }

    /**
     * Only a refusal is held: any other event `laravel-authentication` reports
     * inside a transaction is recorded at once, and is never held.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyARefusalIsHeld(): void
    {
        $fake     = AuditLog::fake();
        $refusals = $this->refusals();
        $inside   = [];
        $held     = null;

        DB::transaction(static function () use ($fake, $refusals, &$inside, &$held): void {

            $held = $refusals->defers(new SessionCreated(new EventContext(self::GUARD, self::client(), sessionId: 'session-1')));

            Event::dispatch(new SessionCreated(new EventContext(self::GUARD, self::client(), sessionId: 'session-2')));

            $inside = self::recorded($fake);
        });

        self::assertFalse($held);
        self::assertSame([['session.created', null]], $inside);
        self::assertSame([['session.created', null]], self::recorded($fake));
    }

    /**
     * Without a transactions manager, as where no application has booted, no
     * refusal is held and no configuration is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutATransactionsManagerNothingIsHeld(): void
    {
        $refusals = $this->refusals();
        $app      = $this->app ?? self::fail('The application has not booted.');

        $app->offsetUnset('db.transactions');
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);

        try {
            self::assertFalse($refusals->defers(self::refusal(FailureReason::INVALID_CREDENTIALS)));
        } finally {
            Facade::setFacadeApplication($app);
        }
    }

    /**
     * A refusal reported inside a savepoint that rolls back waits for the
     * transaction enclosing it, and is recorded once that one has committed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASavepointRolledBackWaitsForTheTransactionEnclosingIt(): void
    {
        $fake  = AuditLog::fake();
        $after = null;

        DB::transaction(static function () use ($fake, &$after): void {

            self::thrownBy(static function (): never {

                DB::transaction(static function (): never {

                    Event::dispatch(self::refusal(FailureReason::METHOD_NOT_ALLOWED));

                    throw new \RuntimeException(self::ROLLED_BACK);
                });
            });

            $after = self::recorded($fake);
        });

        self::assertSame([], $after);
        self::assertSame([[self::SIGN_IN_FAILED, 'method_not_allowed']], self::recorded($fake));
    }

    /**
     * A refusal held again as a savepoint rolls back keeps its place: it is
     * recorded before a refusal reported later in the transaction enclosing it,
     * once that one has committed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalHeldAgainKeepsItsPlace(): void
    {
        $fake = AuditLog::fake();

        DB::transaction(static function (): void {

            self::thrownBy(static function (): never {

                DB::transaction(static function (): never {

                    Event::dispatch(self::refusal(FailureReason::METHOD_NOT_ALLOWED));
                    Event::dispatch(self::refusal(FailureReason::INVALID_CREDENTIALS));

                    throw new \RuntimeException(self::ROLLED_BACK);
                });
            });

            Event::dispatch(self::refusal(FailureReason::SSO_REQUIRED));
        });

        self::assertSame([
            [self::SIGN_IN_FAILED, 'method_not_allowed'],
            [self::SIGN_IN_FAILED, 'invalid_credentials'],
            [self::SIGN_IN_FAILED, 'sso_required'],
        ], self::recorded($fake));
    }

    /**
     * A refusal reported inside a savepoint that commits waits for the
     * transaction enclosing it, and is recorded once that one has rolled back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASavepointCommittedWaitsForTheTransactionEnclosingItToRollBack(): void
    {
        $fake    = AuditLog::fake();
        $after   = null;
        $failure = self::thrownBy(static function () use ($fake, &$after): never {

            DB::transaction(static function () use ($fake, &$after): never {

                DB::transaction(static function (): void {
                    Event::dispatch(self::refusal(FailureReason::METHOD_NOT_ALLOWED));
                });

                $after = self::recorded($fake);

                throw new \RuntimeException(self::ROLLED_BACK);
            });
        });

        self::assertSame(self::ROLLED_BACK, $failure->getMessage());
        self::assertSame([], $after);
        self::assertSame([[self::SIGN_IN_FAILED, 'method_not_allowed']], self::recorded($fake));
    }

    /**
     * Only a transaction on audit-log's storage connection holds a refusal: one
     * open on another connection, which a record written now does not roll back
     * with, holds nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnAnotherConnectionHoldsNothing(): void
    {
        Config::set('database.connections.' . self::OTHER, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        Config::set('audit-log.storage.connection', self::OTHER);

        $fake   = AuditLog::fake();
        $inside = [];

        DB::transaction(static function () use ($fake, &$inside): void {

            Event::dispatch(self::refusal(FailureReason::METHOD_NOT_ALLOWED));

            $inside = self::recorded($fake);
        });

        self::assertSame([[self::SIGN_IN_FAILED, 'method_not_allowed']], $inside);

        DB::connection(self::OTHER)->transaction(static function () use ($fake, &$inside): void {

            Event::dispatch(self::refusal(FailureReason::SSO_REQUIRED));

            $inside = self::recorded($fake);
        });

        self::assertSame([[self::SIGN_IN_FAILED, 'method_not_allowed']], $inside);
        self::assertCount(2, self::recorded($fake));
    }

    /**
     * The transaction a testing trait wraps a test in holds nothing, as it
     * holds no commit callback: a refusal reported inside it alone is recorded
     * at once, and one reported in a transaction opened inside it once that one
     * has committed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTransactionATestIsWrappedInHoldsNothing(): void
    {
        $app     = $this->app ?? self::fail('The application has not booted.');
        $manager = new TestingTransactionsManager([DB::getDefaultConnection()]);

        $app->instance('db.transactions', $manager);
        DB::connection()->setTransactionManager($manager);

        $fake   = AuditLog::fake();
        $inside = null;

        DB::beginTransaction();

        try {
            Event::dispatch(self::refusal(FailureReason::METHOD_NOT_ALLOWED));

            $wrapped = self::recorded($fake);

            DB::transaction(static function () use ($fake, &$inside): void {

                Event::dispatch(self::refusal(FailureReason::SSO_REQUIRED));

                $inside = self::recorded($fake);
            });

            $committed = self::recorded($fake);
        } finally {
            DB::rollBack();
        }

        self::assertSame([[self::SIGN_IN_FAILED, 'method_not_allowed']], $wrapped);
        self::assertSame($wrapped, $inside);
        self::assertSame([
            [self::SIGN_IN_FAILED, 'method_not_allowed'],
            [self::SIGN_IN_FAILED, 'sso_required'],
        ], $committed);
    }

    /**
     * Refusals recorded once their transaction ended are held no more: a later
     * transaction records only its own, and a refusal reported once both have
     * ended is recorded at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordedRefusalIsHeldNoMore(): void
    {
        $fake     = AuditLog::fake();
        $refusals = $this->refusals();

        DB::transaction(static function (): void {
            Event::dispatch(self::refusal(FailureReason::METHOD_NOT_ALLOWED));
        });

        DB::transaction(static function (): void {
            Event::dispatch(self::refusal(FailureReason::INVALID_CREDENTIALS));
        });

        self::assertFalse($refusals->defers(self::refusal(FailureReason::RATE_LIMITED)));

        Event::dispatch(self::refusal(FailureReason::SSO_REQUIRED));

        self::assertSame([
            [self::SIGN_IN_FAILED, 'method_not_allowed'],
            [self::SIGN_IN_FAILED, 'invalid_credentials'],
            [self::SIGN_IN_FAILED, 'sso_required'],
        ], self::recorded($fake));
    }

    /**
     * The refusals held for the request, as the container binds them.
     *
     * @return \SineMacula\Laravel\Iam\Audit\DeferredRefusals
     */
    private function refusals(): DeferredRefusals
    {
        return $this->app?->make(DeferredRefusals::class) ?? self::fail('The application has not booted.');
    }

    /**
     * A refused sign-in on the guard for the reason, about no one.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private static function refusal(FailureReason $reason): AuthenticationFailed
    {
        return new AuthenticationFailed(new EventContext(self::GUARD, self::client()), AuthenticationFlow::SIGN_IN, $reason);
    }

    /**
     * The client every event is reported for.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private static function client(): ClientContext
    {
        return new ClientContext('192.0.2.10', 'iam-tests');
    }

    /**
     * What the call threw, failing when it threw nothing.
     *
     * @param  \Closure(): mixed  $call
     * @return \Throwable
     */
    private static function thrownBy(\Closure $call): \Throwable
    {
        try {
            $call();
        } catch (\Throwable $thrown) {
            return $thrown;
        }

        self::fail('The call threw nothing.');
    }

    /**
     * Every record the fake store holds, in order, as its code and reason.
     *
     * @param  \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore  $fake
     * @return list<array{0: string, 1: ?string}>
     */
    private static function recorded(FakeAuditStore $fake): array
    {
        return array_map(static fn (AuditRecord $record): array => [$record->event, $record->reason], $fake->recorded());
    }
}
