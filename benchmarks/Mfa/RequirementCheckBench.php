<?php

declare(strict_types = 1);

namespace Benchmarks\Mfa;

use Benchmarks\Support\RequirementCheckBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for `laravel-authentication`'s requirement check answered by
 * MFA's (IAM-3.2), the hottest path of the adapters between the two members: it
 * is asked on every sign-in, every pending action and every judgement of a
 * session.
 *
 * Judges a sign-in holding one further proof, and one holding as many as one
 * read returns, through the adapter: the requirement and every proof translated
 * into MFA's, the identity's verification generation read, and MFA's check over
 * them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class RequirementCheckBench
{
    /** @var ?\Benchmarks\Support\RequirementCheckBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?RequirementCheckBenchHarness $harness = null;

    /**
     * Benchmark judging a sign-in with one further proof.
     *
     * @return void
     *
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(100)]
    public function benchOneFurtherProof(): void
    {
        $this->harness()->isMetByOneProof();
    }

    /**
     * Benchmark judging a sign-in with as many further proofs as one read
     * returns.
     *
     * @return void
     *
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(25)]
    public function benchALongSession(): void
    {
        $this->harness()->isMetByALongSession();
    }

    /**
     * Lazily initialise the shared harness.
     *
     * @return \Benchmarks\Support\RequirementCheckBenchHarness
     *
     * @throws \LogicException
     */
    private function harness(): RequirementCheckBenchHarness
    {
        return self::$harness ??= new RequirementCheckBenchHarness;
    }
}
