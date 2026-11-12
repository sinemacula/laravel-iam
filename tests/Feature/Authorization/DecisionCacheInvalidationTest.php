<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation;
use SineMacula\Laravel\Iam\Transactions\ConnectionTransactions;
use Tests\Concerns\RecordsRequirementDecisions;
use Tests\Fixtures\Authorization\Member;
use Tests\TestCase;

/**
 * Feature tests for forgetting decisions on an authentication change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionCacheInvalidation::class)]
#[CoversClass(ConnectionTransactions::class)]
final class DecisionCacheInvalidationTest extends TestCase
{
    use RecordsRequirementDecisions;

    /** @var string The session the change was made in. */
    private const string SESSION = 'the-changed-session';

    /**
     * Rows of `[identity is a model, session]`.
     *
     * @return iterable<string, array{0: bool, 1: ?string}>
     */
    public static function provideChanges(): iterable
    {
        yield 'a model in a session' => [true, self::SESSION];

        yield 'a model in no session' => [true, null];

        yield 'no model in a session' => [false, self::SESSION];

        yield 'no model in no session' => [false, null];
    }

    /**
     * The request's last decision is forgotten whatever the change names.
     *
     * @param  bool  $aModel
     * @param  ?string  $session
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChanges')]
    public function testTheRequestsDecisionsAreForgottenWhateverTheChangeNames(bool $aModel, ?string $session): void
    {
        $this->recordDecision();

        $this->invalidation()->authenticationChanged($aModel ? self::identity(7) : new \stdClass, $session);

        self::assertNull($this->lastDecision());
    }

    /**
     * A decision recorded before a rollback is forgotten again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADecisionRecordedBeforeARollbackIsForgottenAgain(): void
    {
        $identity = self::identity(7);

        DB::beginTransaction();

        $this->recordDecision();

        $this->invalidation()->authenticationChanged($identity, self::SESSION);

        self::assertNull($this->lastDecision());

        $this->recordDecision();

        DB::rollBack();

        self::assertNull($this->lastDecision());
    }

    /**
     * A committed savepoint still waits on the enclosing transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADecisionRecordedAfterACommittedSavepointIsForgottenWhenTheEnclosingTransactionRollsBack(): void
    {
        $identity = self::identity(7);

        DB::beginTransaction();

        DB::transaction(fn () => $this->invalidation()->authenticationChanged($identity, self::SESSION));

        $manager = $this->app?->make('db.transactions');

        self::assertInstanceOf(DatabaseTransactionsManager::class, $manager);

        $enclosing = $manager->callbackApplicableTransactions()->first();

        self::assertInstanceOf(DatabaseTransactionRecord::class, $enclosing);
        self::assertCount(1, $enclosing->getCallbacksForRollback());

        $this->recordDecision();

        DB::rollBack();

        self::assertNull($this->lastDecision());
    }

    /**
     * Outside a transaction the decision is forgotten at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOutsideATransactionTheChangeWaitsOnNothing(): void
    {
        $identity = self::identity(7);

        $this->invalidation()->authenticationChanged($identity, self::SESSION);

        $decision = $this->recordDecision();

        DB::beginTransaction();
        DB::rollBack();

        self::assertSame($decision, $this->lastDecision());
    }

    /**
     * A decision recorded before a commit is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADecisionRecordedBeforeACommitIsKept(): void
    {
        $identity = self::identity(7);

        DB::beginTransaction();

        $this->invalidation()->authenticationChanged($identity, self::SESSION);

        $decision = $this->recordDecision();

        DB::commit();

        self::assertSame($decision, $this->lastDecision());
    }

    /**
     * An identity of the key given, never saved.
     *
     * @param  int  $key
     * @return \Tests\Fixtures\Authorization\Member
     */
    private static function identity(int $key): Member
    {
        $identity = new Member;

        $identity->setAttribute($identity->getKeyName(), $key);

        return $identity;
    }

    /**
     * The invalidation, as the MFA adapters resolve it.
     *
     * @return \SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function invalidation(): DecisionCacheInvalidation
    {
        $invalidation = $this->app?->make(DecisionCacheInvalidation::class);

        self::assertInstanceOf(DecisionCacheInvalidation::class, $invalidation);

        return $invalidation;
    }
}
