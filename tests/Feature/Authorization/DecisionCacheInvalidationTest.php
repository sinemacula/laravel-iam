<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation;
use SineMacula\Laravel\Iam\Transactions\OpenTransactions;
use Tests\Concerns\RecordsRequirementDecisions;
use Tests\Fixtures\Authorization\Member;
use Tests\TestCase;

/**
 * Feature tests for having `laravel-authorization` forget the decisions of the
 * request once an identity's authentication changes (IAM-6.11): the request's
 * last decision is forgotten whatever it read and whoever it was about, the
 * identity a model or not, a session named or none; and a decision recorded
 * after the change is forgotten again should the transaction on the storage
 * connection roll back, the enclosing one included when the change was made in
 * a savepoint that committed, but kept once it commits. Every decision is
 * recorded and read through `laravel-authorization`'s facade.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionCacheInvalidation::class)]
#[CoversClass(OpenTransactions::class)]
final class DecisionCacheInvalidationTest extends TestCase
{
    use RecordsRequirementDecisions;

    /** @var string The session the change was made in. */
    private const string SESSION = 'the-changed-session';

    /**
     * Rows of `[whether the identity whose authentication changed is a model,
     * the session it changed in]`.
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
     * The request's last decision is forgotten whatever the change names, even
     * one that read no authentication requirement, about nobody, made in no
     * session: `laravel-authorization` forgets every decision of the request.
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
     * A decision recorded after the change, inside the transaction on the
     * storage connection, is forgotten again when that transaction rolls back,
     * since the proofs it read were never committed.
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
     * A change made inside a savepoint that commits, as MFA's own transaction
     * is when the caller opened one, waits on the enclosing transaction too: a
     * decision recorded after it is forgotten again when the enclosing
     * transaction rolls back, on every version of Laravel, including one that
     * never tells a savepoint that has committed of that rollback.
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
     * An application holding no transactions manager, or one that is not
     * Laravel's, has no transaction's end to wait on: the change forgets the
     * decision at once, and waits on nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoTransactionsManagerTheChangeForgetsAtOnce(): void
    {
        $app      = $this->app ?? self::fail('The application has not booted.');
        $identity = self::identity(7);

        DB::beginTransaction();

        $this->recordDecision();

        $app->instance('db.transactions', new \stdClass);

        try {
            $this->invalidation()->authenticationChanged($identity, self::SESSION);
        } finally {
            unset($app['db.transactions']);
        }

        self::assertNull($this->lastDecision());

        DB::rollBack();
    }

    /**
     * Outside any transaction, the change forgets the decision at once, and
     * waits on nothing.
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
     * A decision recorded after the change, inside the transaction on the
     * storage connection, is kept once that transaction commits, since it read
     * the proofs that committed.
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
