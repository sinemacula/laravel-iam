<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Audit\CallerSnapshot;
use SineMacula\Laravel\Iam\Audit\JobCallers;

/**
 * Unit tests for the callers the queued jobs running carried (IAM-9.7): none
 * outside a job; the innermost job's caller, or none for a job that carried
 * none; a job left with every job inside it, the outer job's caller back in
 * force; and leaving a job twice, or one never entered, changing nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JobCallers::class)]
final class JobCallersTest extends TestCase
{
    /**
     * Outside any job there is no carried caller.
     *
     * @return void
     */
    public function testOutsideAJobThereIsNoCaller(): void
    {
        self::assertNull((new JobCallers)->current());
    }

    /**
     * The innermost job's caller is the one in force, and a job that carried
     * none carries none, even inside one that did.
     *
     * @return void
     */
    public function testTheInnermostJobsCallerIsInForce(): void
    {
        $callers = new JobCallers;
        $outer   = self::caller('1');
        $inner   = self::caller('2');

        $callers->enter(new \stdClass, $outer);

        self::assertSame($outer, $callers->current());

        $callers->enter(new \stdClass, $inner);

        self::assertSame($inner, $callers->current());

        $callers->enter(new \stdClass, null);

        self::assertNull($callers->current());
    }

    /**
     * Leaving a job leaves every job inside it too, and brings back the caller
     * of the job around it.
     *
     * @return void
     */
    public function testLeavingAJobLeavesTheJobsInsideIt(): void
    {
        $callers = new JobCallers;
        $outer   = self::caller('1');
        $middle  = new \stdClass;

        $callers->enter(new \stdClass, $outer);
        $callers->enter($middle, self::caller('2'));
        $callers->enter(new \stdClass, self::caller('3'));

        $callers->leave($middle);

        self::assertSame($outer, $callers->current());
    }

    /**
     * The innermost frame of a job entered twice is the one left.
     *
     * @return void
     */
    public function testTheInnermostFrameOfAJobIsLeft(): void
    {
        $callers = new JobCallers;
        $job     = new \stdClass;
        $first   = self::caller('1');

        $callers->enter($job, $first);
        $callers->enter($job, self::caller('2'));

        $callers->leave($job);

        self::assertSame($first, $callers->current());
    }

    /**
     * Leaving a job twice, or one never entered, changes nothing, as a failed
     * job reports its end twice.
     *
     * @return void
     */
    public function testLeavingAgainChangesNothing(): void
    {
        $callers = new JobCallers;
        $outer   = self::caller('1');
        $job     = new \stdClass;

        $callers->enter(new \stdClass, $outer);
        $callers->enter($job, self::caller('2'));

        $callers->leave($job);
        $callers->leave($job);
        $callers->leave(new \stdClass);

        self::assertSame($outer, $callers->current());
    }

    /**
     * A caller of the identifier given.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Iam\Audit\CallerSnapshot
     */
    private static function caller(string $id): CallerSnapshot
    {
        return new CallerSnapshot('api', 'person', $id);
    }
}
