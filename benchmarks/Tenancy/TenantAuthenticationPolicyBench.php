<?php

declare(strict_types = 1);

namespace Benchmarks\Tenancy;

use Benchmarks\Support\TenantAuthenticationPolicyBenchHarness;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;

/**
 * PHPBench suite for the tenant authentication policy this package binds
 * (IAM-4.5), the composite of SSO's enforcement, SSO's exemption gate and the
 * application's tenant MFA requirement: `laravel-authentication` asks it on
 * every sign-in in a tenant, every activation, refresh and switch, sometimes
 * under the session's row lock, so its cost is held while the lock is.
 *
 * Answers a sign-in with SSO's enforcement off and no requirement, which reads
 * nothing, and one with a rule through the redemption's connection and a
 * requirement held in memory, so the measure is the adapter's own work: the
 * sign-in's connection asked, the answer composed and its version digested.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final class TenantAuthenticationPolicyBench
{
    /** @var ?\Benchmarks\Support\TenantAuthenticationPolicyBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?TenantAuthenticationPolicyBenchHarness $nothingOn = null;

    /** @var ?\Benchmarks\Support\TenantAuthenticationPolicyBenchHarness @managed-static Reused across phpbench iterations. */
    private static ?TenantAuthenticationPolicyBenchHarness $enforced = null;

    /**
     * Benchmark answering a sign-in with nothing on.
     *
     * @return void
     *
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(1000)]
    public function benchNothingOn(): void
    {
        (self::$nothingOn ??= new TenantAuthenticationPolicyBenchHarness)->answers();
    }

    /**
     * Benchmark answering a sign-in with a rule and a requirement.
     *
     * @return void
     *
     * @throws \LogicException
     */
    #[Iterations(5)]
    #[Revs(1000)]
    public function benchAnEnforcedRequirement(): void
    {
        (self::$enforced ??= new TenantAuthenticationPolicyBenchHarness(enforced: true))->answers();
    }
}
