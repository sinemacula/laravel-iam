<?php

declare(strict_types = 1);

namespace Tests\Unit\Transactions;

use Illuminate\Database\Connection;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Transactions\CommittedWork;

/**
 * Unit tests for the work held until a connection's transaction has committed:
 * a release runs its own connection's work alone, in the order it was held,
 * once, a nameless connection's under an empty name; each piece is held under a
 * ticket of its own, which a rollback drops it by, alone; the connections work
 * is held for are listed until their work is released or dropped; work that
 * releases again releases nothing twice; and the first failure is rethrown once
 * every piece has run.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CommittedWork::class)]
final class CommittedWorkTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var list<string> What ran, in the order it ran. */
    private array $ran = [];

    /**
     * A release runs the work held for its own connection, in the order it was
     * held, and leaves another connection's waiting for that one's release.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReleaseRunsItsOwnConnectionsWorkInOrder(): void
    {
        $work    = new CommittedWork;
        $storage = self::connection('storage');
        $other   = self::connection('other');

        $work->hold($storage, $this->noted('first'));
        $work->hold($other, $this->noted('elsewhere'));
        $work->hold($storage, $this->noted('second'));

        $work->release($storage);

        self::assertSame(['first', 'second'], $this->ran);
        self::assertSame([$other], $work->connections());

        $work->release($other);

        self::assertSame(['first', 'second', 'elsewhere'], $this->ran);
        self::assertSame([], $work->connections());
    }

    /**
     * Work released once is never released again, by a later release or by a
     * release the work makes itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWorkIsReleasedOnce(): void
    {
        $work    = new CommittedWork;
        $storage = self::connection('storage');

        $work->hold($storage, function () use ($work, $storage): void {
            $this->ran[] = 'work';

            $work->release($storage);
        });

        $work->release($storage);
        $work->release($storage);

        self::assertSame(['work'], $this->ran);
    }

    /**
     * Each piece is held under a ticket of its own, and dropping one leaves the
     * rest held, the connection listed while any is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADroppedPieceIsDroppedAlone(): void
    {
        $work    = new CommittedWork;
        $storage = self::connection('storage');
        $first   = $work->hold($storage, $this->noted('first'));
        $second  = $work->hold($storage, $this->noted('second'));
        $third   = $work->hold($storage, $this->noted('third'));

        self::assertSame([0, 1, 2], [$first, $second, $third]);

        $work->drop($storage, $second);

        self::assertSame([$storage], $work->connections());

        $work->release($storage);

        self::assertSame(['first', 'third'], $this->ran);
    }

    /**
     * Dropping every piece held for a connection stops listing it, and a ticket
     * dropped twice, or never held, changes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDroppingEveryPieceForgetsTheConnection(): void
    {
        $work    = new CommittedWork;
        $storage = self::connection('storage');
        $other   = self::connection('other');
        $ticket  = $work->hold($storage, $this->noted('dropped'));

        $work->hold($other, $this->noted('other'));

        $work->drop($storage, $ticket);
        $work->drop($storage, $ticket);
        $work->drop($other, 99);

        self::assertSame([$other], $work->connections());

        $work->release($storage);
        $work->release($other);

        self::assertSame(['other'], $this->ran);
    }

    /**
     * A connection Laravel knows by no name has its work held under an empty
     * name, as any other connection has its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANamelessConnectionsWorkIsHeldUnderAnEmptyName(): void
    {
        $work = new CommittedWork;

        $work->hold(self::connection(null), $this->noted('nameless'));
        $work->hold(self::connection('storage'), $this->noted('storage'));

        $work->release(self::connection(''));

        self::assertSame(['nameless'], $this->ran);
    }

    /**
     * A release with nothing held runs nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReleaseWithNothingHeldRunsNothing(): void
    {
        $work = new CommittedWork;

        $work->release(self::connection('storage'));

        self::assertSame([], $this->ran);
        self::assertSame([], $work->connections());
    }

    /**
     * Every piece released runs though one before it fails, and the first
     * failure is rethrown once they have, the connection no longer listed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFirstFailureIsRethrownOnceEveryPieceHasRun(): void
    {
        $work    = new CommittedWork;
        $storage = self::connection('storage');
        $first   = new \RuntimeException('The first piece failed.');
        $second  = new \LogicException('The second piece failed.');

        $work->hold($storage, static fn () => throw $first);
        $work->hold($storage, static fn () => throw $second);
        $work->hold($storage, $this->noted('third'));

        try {
            $work->release($storage);

            self::fail('No failure was rethrown.');
        } catch (\RuntimeException $exception) {
            self::assertSame($first, $exception);
        }

        self::assertSame(['third'], $this->ran);
        self::assertSame([], $work->connections());
    }

    /**
     * Work that notes its name each time it runs.
     *
     * @param  string  $name
     * @return \Closure(): void
     */
    private function noted(string $name): \Closure
    {
        return function () use ($name): void {
            $this->ran[] = $name;
        };
    }

    /**
     * A connection of the name.
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
