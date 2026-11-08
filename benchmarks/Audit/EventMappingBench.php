<?php

declare(strict_types = 1);

namespace Benchmarks\Audit;

use Benchmarks\Support\EventMappingBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for mapping the members' events into audit-log's records
 * (IAM-9.1, IAM-9.4): the work this package adds to every event a member
 * dispatches, synchronously, inside the flow that dispatched it.
 *
 * Maps a sign-in under audit-log's own code, a refused sign-in for a concealed
 * reason with its identifier and challenge, an MFA step-up's verification
 * correlated by its challenge, and an SSO redemption correlated as its sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class EventMappingBench
{
    /** @var ?\Benchmarks\Support\EventMappingBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?EventMappingBenchHarness $harness = null;

    /**
     * Benchmark mapping a sign-in.
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
        $this->harness()->mapsASignIn();
    }

    /**
     * Benchmark mapping a refused sign-in.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(1000)]
    public function benchARefusal(): void
    {
        $this->harness()->mapsARefusal();
    }

    /**
     * Benchmark mapping an MFA verification.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(1000)]
    public function benchAVerification(): void
    {
        $this->harness()->mapsAVerification();
    }

    /**
     * Benchmark mapping an SSO redemption.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(1000)]
    public function benchARedemption(): void
    {
        $this->harness()->mapsARedemption();
    }

    /**
     * Lazily initialise the shared harness.
     *
     * @return \Benchmarks\Support\EventMappingBenchHarness
     */
    private function harness(): EventMappingBenchHarness
    {
        return self::$harness ??= new EventMappingBenchHarness;
    }
}
