<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use Tests\Fixtures\Mfa\Freshness\RecordsReadModes;

/**
 * Binds `laravel-authentication`'s freshness policy decorated to record the
 * read mode each freshness judgement is asked in (`RecordsReadModes`), and
 * asserts how an adapter asked it: current inside a transaction on the session
 * model's connection, plainly outside one. It also asserts which adapter asked
 * each judgement, and for which operation, so a judgement asked on another path
 * to the same policy never stands in for the adapter's own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait RecordsFreshnessReadModes
{
    /**
     * Bind the recording policy for the rest of the test, and return it.
     *
     * @return \Tests\Fixtures\Mfa\Freshness\RecordsReadModes
     */
    protected function recordReadModes(): RecordsReadModes
    {
        $policy = $this->app?->make(ConfiguredFreshness::class);

        self::assertInstanceOf(ConfiguredFreshness::class, $policy);

        $recorder = new RecordsReadModes($policy);

        $this->app?->instance(FreshnessPolicy::class, $recorder);

        return $recorder;
    }

    /**
     * Assert at least one freshness judgement was asked, and every one in the
     * read mode given.
     *
     * @param  \Tests\Fixtures\Mfa\Freshness\RecordsReadModes  $recorder
     * @param  bool  $current
     * @return void
     */
    protected static function assertAskedOnlyIn(RecordsReadModes $recorder, bool $current): void
    {
        self::assertNotSame([], $recorder->modes, 'No freshness judgement was asked.');
        self::assertSame(array_fill(0, count($recorder->modes), $current), $recorder->modes, $current ? 'A judgement was asked plainly.' : 'A judgement was asked current.');
    }

    /**
     * Assert the adapter given asked at least one freshness judgement for the
     * operation given, and every judgement asked was its, for that operation.
     *
     * @param  \Tests\Fixtures\Mfa\Freshness\RecordsReadModes  $recorder
     * @param  class-string  $adapter
     * @param  string  $operation
     * @return void
     */
    protected static function assertAskedOnlyBy(RecordsReadModes $recorder, string $adapter, string $operation): void
    {
        $described = static fn (?string $asker, string $asked): string => ($asker ?? 'none of this package\'s adapters') . ' for ' . $asked;
        $listing   = implode(', ', array_map($described, $recorder->askers, $recorder->operations));

        self::assertNotSame([], $recorder->askers, 'No freshness judgement was asked.');
        self::assertSame(array_fill(0, count($recorder->askers), $adapter), $recorder->askers, 'Asked by ' . $listing . '.');
        self::assertSame(array_fill(0, count($recorder->operations), $operation), $recorder->operations, 'Asked by ' . $listing . '.');
    }
}
