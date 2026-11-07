<?php

declare(strict_types = 1);

namespace Tests\Unit\Transactions;

use Illuminate\Database\Connection;
use Illuminate\Database\Events\TransactionCommitting;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Transactions\OutermostCommits;

/**
 * Unit tests for counting the outermost commits each connection begins: each is
 * counted for its own connection, by its name, a nameless connection included,
 * and a connection that began none counts none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutermostCommits::class)]
final class OutermostCommitsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A connection that began no commit counts none.
     *
     * @return void
     */
    public function testAConnectionThatBeganNoCommitCountsNone(): void
    {
        self::assertSame(0, (new OutermostCommits)->count(self::connection('storage')));
    }

    /**
     * Each commit is counted for the connection that began it, and for no
     * other.
     *
     * @return void
     */
    public function testEachCommitIsCountedForItsOwnConnection(): void
    {
        $commits = new OutermostCommits;

        $commits->committing(new TransactionCommitting(self::connection('storage')));
        $commits->committing(new TransactionCommitting(self::connection('storage')));
        $commits->committing(new TransactionCommitting(self::connection('other')));

        self::assertSame(2, $commits->count(self::connection('storage')));
        self::assertSame(1, $commits->count(self::connection('other')));
        self::assertSame(0, $commits->count(self::connection('elsewhere')));
    }

    /**
     * A connection Laravel knows by no name is counted as any other, under an
     * empty name.
     *
     * @return void
     */
    public function testANamelessConnectionIsCounted(): void
    {
        $commits = new OutermostCommits;

        $commits->committing(new TransactionCommitting(self::connection(null)));

        self::assertSame(1, $commits->count(self::connection(null)));
        self::assertSame(1, $commits->count(self::connection('')));
        self::assertSame(0, $commits->count(self::connection('storage')));
    }

    /**
     * A connection of the name given.
     *
     * @param  ?string  $name
     * @return \Illuminate\Database\Connection
     */
    private static function connection(?string $name): Connection
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->allows('getName')->andReturn($name);

        return $connection;
    }
}
