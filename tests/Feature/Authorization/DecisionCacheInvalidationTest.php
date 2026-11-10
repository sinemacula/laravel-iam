<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation;
use SineMacula\Laravel\Iam\Transactions\OpenTransactions;
use Tests\Fixtures\Authorization\Member;
use Tests\TestCase;

/**
 * Feature tests for forgetting the decision `laravel-authorization` keeps that
 * depended on an identity's authentication (IAM-6.11): the request's last
 * decision is forgotten when it read an authentication requirement and was made
 * in the session named or was about the identity, and kept when it read none,
 * or was about another identity in another session; with no session named, only
 * a decision about the identity is forgotten, never one made outside any
 * session about someone else; an identity that is no model is matched by the
 * session alone; a decision made in the session is forgotten even when a met
 * requirement it read lapses while it is compared; and a decision recorded
 * after the change is forgotten again should the transaction on the storage
 * connection roll back, the enclosing one included when the change was made in
 * a savepoint that committed, but kept once it commits.
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
    /** @var string The session the change was made in. */
    private const string SESSION = 'the-changed-session';

    /** @var string Another session. */
    private const string OTHER_SESSION = 'another-session';

    /**
     * Rows of `[the session the decision was made in, whether it read a
     * requirement, whether it was about the identity, whether it is
     * forgotten]`.
     *
     * @return iterable<string, array{0: ?string, 1: bool, 2: bool, 3: bool}>
     */
    public static function provideDecisions(): iterable
    {
        yield 'a requirement read in the session' => [self::SESSION, true, false, true];

        yield 'a requirement read about the identity in another session' => [self::OTHER_SESSION, true, true, true];

        yield 'a requirement read about the identity outside any session' => [null, true, true, true];

        yield 'a requirement read about someone else in another session' => [self::OTHER_SESSION, true, false, false];

        yield 'a requirement read about someone else outside any session' => [null, true, false, false];

        yield 'no requirement read in the session' => [self::SESSION, false, true, false];
    }

    /**
     * The last decision is forgotten exactly when it read a requirement and was
     * made in the session named or was about the identity.
     *
     * @param  ?string  $session
     * @param  bool  $readARequirement
     * @param  bool  $aboutTheIdentity
     * @param  bool  $forgotten
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDecisions')]
    public function testTheLastDecisionIsForgottenWhenItDependedOnTheChange(?string $session, bool $readARequirement, bool $aboutTheIdentity, bool $forgotten): void
    {
        $identity = self::identity(7);
        $decision = $this->record($session, $readARequirement, $aboutTheIdentity ? $identity : self::identity(8));

        $this->invalidation()->authenticationChanged($identity, self::SESSION);

        self::assertSame($forgotten ? null : $decision, $this->store()->get());
    }

    /**
     * With no session named, as a reset names none, a decision about the
     * identity is forgotten and one made outside any session about someone else
     * is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoSessionNamedOnlyTheIdentityIsMatched(): void
    {
        $identity = self::identity(7);
        $kept     = $this->record(null, true, self::identity(8));

        $this->invalidation()->authenticationChanged($identity);

        self::assertSame($kept, $this->store()->get());

        $this->record(self::SESSION, true, $identity);

        $this->invalidation()->authenticationChanged($identity);

        self::assertNull($this->store()->get());
    }

    /**
     * An identity that is no model is matched by the session alone, whoever the
     * decision was about, and a decision whose provenance names no identity by
     * the session alone too, whoever the change was made to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatIsNoModelIsMatchedByTheSessionAlone(): void
    {
        $identity = new \stdClass;
        $kept     = $this->record(self::OTHER_SESSION, true, null);

        $this->invalidation()->authenticationChanged($identity, self::SESSION);

        self::assertSame($kept, $this->store()->get());

        $this->record(self::SESSION, true, null);

        $this->invalidation()->authenticationChanged($identity, self::SESSION);

        self::assertNull($this->store()->get());

        $kept = $this->record(self::OTHER_SESSION, true, self::identity(7));

        $this->invalidation()->authenticationChanged($identity, self::SESSION);

        self::assertSame($kept, $this->store()->get());

        $kept = $this->record(self::OTHER_SESSION, true, null);

        $this->invalidation()->authenticationChanged(self::identity(7), self::SESSION);

        self::assertSame($kept, $this->store()->get());
    }

    /**
     * A decision made in the session named is forgotten by its session alone,
     * even when a met requirement it read lapses between the store handing it
     * over and the session being compared, so it is never kept for a later read
     * once its expiry is moved or ignored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADecisionMadeInTheSessionIsForgottenWhateverItsExpiry(): void
    {
        $start = Carbon::parse('2026-11-09 12:00:00');
        $reads = 0;

        $decision = Decision::allow(DecisionStage::ALLOW)->withFreshness(new RequirementFreshness(self::SESSION, $start->toImmutable()->addSecond()));

        $this->store()->put($decision, new DecisionProvenance(identity: Reference::of(self::identity(8))), self::SESSION);

        Carbon::setTestNow(static function () use ($start, &$reads): Carbon {
            return $reads++ === 0 ? $start->copy() : $start->copy()->addSeconds(2);
        });

        try {
            $this->invalidation()->authenticationChanged(self::identity(7), self::SESSION);
        } finally {
            Carbon::setTestNow();
        }

        self::assertNull($this->store()->provenance());
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

        $this->record(self::SESSION, true, $identity);

        $this->invalidation()->authenticationChanged($identity, self::SESSION);

        self::assertNull($this->store()->get());

        $this->record(self::SESSION, true, $identity);

        DB::rollBack();

        self::assertNull($this->store()->get());
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

        $this->record(self::SESSION, true, $identity);

        DB::rollBack();

        self::assertNull($this->store()->get());
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

        $this->record(self::SESSION, true, $identity);

        $app->instance('db.transactions', new \stdClass);

        try {
            $this->invalidation()->authenticationChanged($identity, self::SESSION);
        } finally {
            unset($app['db.transactions']);
        }

        self::assertNull($this->store()->get());

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

        $decision = $this->record(self::SESSION, true, $identity);

        DB::beginTransaction();
        DB::rollBack();

        self::assertSame($decision, $this->store()->get());
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

        $decision = $this->record(self::SESSION, true, $identity);

        DB::commit();

        self::assertSame($decision, $this->store()->get());
    }

    /**
     * Record an allow as the last decision, made in the session given, having
     * read a requirement or not, about the identity given.
     *
     * @param  ?string  $session
     * @param  bool  $readARequirement
     * @param  ?\Tests\Fixtures\Authorization\Member  $identity
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     *
     * @throws \Throwable
     */
    private function record(?string $session, bool $readARequirement, ?Member $identity): Decision
    {
        $decision = Decision::allow(DecisionStage::ALLOW);
        $decision = $readARequirement ? $decision->withFreshness(new RequirementFreshness($session)) : $decision;

        $this->store()->put($decision, new DecisionProvenance(identity: $identity === null ? null : Reference::of($identity)), $session);

        return $decision;
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
     * The request's store of the last decision.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(): LastDecisionStore
    {
        $store = $this->app?->make(LastDecisionStore::class);

        self::assertInstanceOf(LastDecisionStore::class, $store);

        return $store;
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
