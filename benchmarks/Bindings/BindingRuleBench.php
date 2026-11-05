<?php

declare(strict_types = 1);

namespace Benchmarks\Bindings;

use Benchmarks\Support\BindingRuleBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for the binding rule (IAM-8.4).
 *
 * Applies a seam table the size of the package's full one over the members'
 * real binding table, on the three paths the booting phase can take: binding
 * over the members' defaults, keeping the application's bindings, and a table
 * whose every switch is off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class BindingRuleBench
{
    /** @var ?\Benchmarks\Support\BindingRuleBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?BindingRuleBenchHarness $harness = null;

    /**
     * Benchmark binding every adapter over the members' defaults.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchOverMemberDefaults(): void
    {
        $this->harness()->runOverMemberDefaults();
    }

    /**
     * Benchmark keeping every binding the application made.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchOverApplicationBindings(): void
    {
        $this->harness()->runOverApplicationBindings();
    }

    /**
     * Benchmark a table whose every switch is off.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchSwitchedOff(): void
    {
        $this->harness()->runSwitchedOff();
    }

    /**
     * Lazily initialise the shared harness.
     *
     * @return \Benchmarks\Support\BindingRuleBenchHarness
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function harness(): BindingRuleBenchHarness
    {
        return self::$harness ??= new BindingRuleBenchHarness;
    }
}
