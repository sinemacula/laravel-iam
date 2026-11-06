<?php

declare(strict_types = 1);

namespace Benchmarks\Sso;

use Benchmarks\Support\ExternalResultsBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for building `laravel-authentication`'s external result from a
 * redemption SSO admitted (IAM-4.1, IAM-4.2): the one piece of each redemption
 * this package computes itself, inside the redemption's transaction and under
 * SSO's locks, so its cost is held while the locks are.
 *
 * Builds a sign-in's result, with its evidence and the captured provenance as
 * the provider context, and a re-authentication's, with the renewal's time and
 * evidence and no provider context.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class ExternalResultsBench
{
    /** @var ?\Benchmarks\Support\ExternalResultsBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?ExternalResultsBenchHarness $harness = null;

    /**
     * Benchmark building a sign-in's external result.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(1000)]
    public function benchASignIn(): void
    {
        $this->harness()->buildsASignIn();
    }

    /**
     * Benchmark building a re-authentication's external result.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(1000)]
    public function benchARenewal(): void
    {
        $this->harness()->buildsARenewal();
    }

    /**
     * Lazily initialise the shared harness.
     *
     * @return \Benchmarks\Support\ExternalResultsBenchHarness
     */
    private function harness(): ExternalResultsBenchHarness
    {
        return self::$harness ??= new ExternalResultsBenchHarness;
    }
}
