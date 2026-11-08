<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks\Contracts;

/**
 * One of this package's own checks, which `iam:check` runs after every member's
 * (IAM-10.1, IAM-10.2).
 *
 * It mirrors SSO's configuration check contract, so a check of SSO's side can
 * register there as well (IAM-10.3): it applies only to what is on, and each of
 * its checks is a closure that throws an exception whose message names one
 * problem, so one run reports every problem. A closure that finds nothing to
 * refuse but something the application should know (a setting this package does
 * not require, left as it is) returns that note instead, which is reported
 * without failing the run; any other return is no finding.
 *
 * A check reads configuration and the container only: it never resolves a
 * guard's caller, reads a request or opens a database connection, so it runs
 * the same at deploy as anywhere else. It is resolved from the container each
 * time `iam:check` runs, so it reads the configuration as it is then, and
 * building it must not depend on what it covers being on. A message names the
 * key, the seam or the guard, never a configured secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface Check
{
    /**
     * The subject the check's findings are reported under.
     *
     * @return string
     */
    public function subject(): string;

    /**
     * Whether what the check covers is on. It must not throw.
     *
     * @return bool
     */
    public function applies(): bool;

    /**
     * The checks, each a closure that throws for a problem, returns a note for
     * something to report without failing, and returns nothing otherwise.
     *
     * @return list<\Closure(): mixed>
     */
    public function checks(): array;
}
