<?php

declare(strict_types = 1);

namespace Tests\Unit\Sso;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Database\ConcurrencyErrorDetector;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Foundation\Auth\User;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Sso\Callers;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Sso\LinkRedemption;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Iam\Transactions\ConcurrencyFailures;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Iam\Transactions\OutermostCommits;
use SineMacula\Laravel\Iam\Transactions\RetrySettings;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use Tests\Fixtures\Sso\SessionGuards;

/**
 * Unit tests for telling, on a storage connection Laravel knows by no name,
 * whether a standalone `link` attempt reached its commit before it failed: an
 * attempt that did is not run again, and one that did not is, so a nameless
 * connection is counted as any other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkRedemption::class)]
#[CoversClass(OutermostCommits::class)]
final class LinkRedemptionTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A concurrency failure met once the attempt began its commit on a nameless
     * connection reaches the caller from the first attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttemptThatReachedItsCommitOnANamelessConnectionIsNotRunAgain(): void
    {
        $connection = self::namelessConnection();
        $failure    = new \RuntimeException('Deadlock found when trying to get lock; try restarting transaction');
        $calls      = new \ArrayObject;
        $container  = new Container;
        $commits    = new OutermostCommits;

        $container->instance(OutermostCommits::class, $commits);
        $container->bind(HandoffRedemption::class, static fn (): object => new class ($connection, $commits, $failure, $calls) {
            /**
             * Constructor.
             *
             * @param  \Illuminate\Database\Connection  $connection
             * @param  \SineMacula\Laravel\Iam\Transactions\OutermostCommits  $commits
             * @param  \Throwable  $failure
             * @param  \ArrayObject<int, true>  $calls
             */
            public function __construct(

                /** The connection whose commit the attempt begins. */
                private readonly Connection $connection,

                /** Counts the commit begun. */
                private readonly OutermostCommits $commits,

                /** What the attempt fails on once its commit has begun. */
                private readonly \Throwable $failure,

                /** Records each attempt. */
                private readonly \ArrayObject $calls,
            ) {}

            /**
             * Begin the commit, then fail.
             *
             * @return never
             *
             * @throws \Throwable
             */
            public function redeem(): never
            {
                $this->calls->append(true);
                $this->commits->committing(new TransactionCommitting($this->connection));

                throw $this->failure;
            }
        });

        try {
            self::redemption($container, $connection)->redeem('connection-1', 'code', 'verifier', new ClientContext(null, null), self::caller());

            self::fail('A failure once the attempt had begun its commit was swallowed.');
        } catch (\RuntimeException $thrown) {
            self::assertSame($failure, $thrown);
        }

        self::assertCount(1, $calls);
        self::assertSame(1, $commits->count($connection));
    }

    /**
     * A concurrency failure met before the attempt began its commit on a
     * nameless connection is redeemed again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttemptThatFailedBeforeItsCommitOnANamelessConnectionIsRunAgain(): void
    {
        $connection = self::namelessConnection();
        $refused    = RedemptionResult::refused(FailureReason::HANDOFF_UNKNOWN);
        $calls      = new \ArrayObject;
        $container  = new Container;

        $container->instance(OutermostCommits::class, new OutermostCommits);
        $container->bind(HandoffRedemption::class, static fn (): object => new class ($refused, $calls) {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $refused
             * @param  \ArrayObject<int, true>  $calls
             */
            public function __construct(

                /** What the second attempt answers. */
                private readonly RedemptionResult $refused,

                /** Records each attempt. */
                private readonly \ArrayObject $calls,
            ) {}

            /**
             * Fail the first attempt, and answer the next.
             *
             * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
             *
             * @throws \RuntimeException
             */
            public function redeem(): RedemptionResult
            {
                $this->calls->append(true);

                return $this->calls->count() === 1 ? throw new \RuntimeException('Deadlock found when trying to get lock; try restarting transaction') : $this->refused;
            }
        });

        self::assertSame($refused, self::redemption($container, $connection)->redeem('connection-1', 'code', 'verifier', new ClientContext(null, null), self::caller()));
        self::assertCount(2, $calls);
    }

    /**
     * A storage connection with no transaction open, which Laravel knows by no
     * name.
     *
     * @return \Illuminate\Database\Connection
     */
    private static function namelessConnection(): Connection
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->allows('transactionLevel')->andReturn(0);
        $connection->allows('getName')->andReturn(null);

        return $connection;
    }

    /**
     * The link redemption on the connection, resolving SSO's redemption and the
     * commits from the container, with every failure a concurrency one.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  \Illuminate\Database\Connection  $connection
     * @return \SineMacula\Laravel\Iam\Sso\LinkRedemption
     */
    private static function redemption(Container $container, Connection $connection): LinkRedemption
    {
        $database = \Mockery::mock(DatabaseManager::class);
        $detector = \Mockery::mock(ConcurrencyErrorDetector::class);

        $database->allows('connection')->andReturn($connection);
        $detector->allows('causedByConcurrencyError')->andReturn(true);

        $storage  = new StorageConnection(new Repository);
        $settings = new RetrySettings(new Repository);
        $failures = new ConcurrencyFailures($detector);

        $transaction = new CrossMemberTransaction($database, $storage, $settings, $failures);

        return new LinkRedemption($container, new Callers(new IdentityReferences, SessionGuards::resolving('api')), $database, $storage, $settings, $failures, $transaction);
    }

    /**
     * The caller a link is redeemed as: an Eloquent identity with a key, on the
     * `api` guard, holding no session.
     *
     * @return \SineMacula\Laravel\Authentication\Callers\Caller
     */
    private static function caller(): Caller
    {
        return new Caller('api', CallerCredential::ACCESS, (new class extends User implements Identity {})->forceFill(['id' => 7]), null, null, null);
    }
}
