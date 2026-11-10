<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks\Contracts;

/**
 * One of this package's checks that checks `laravel-authentication`'s side too,
 * which `authentication:check` reports as well as `iam:check` (IAM-10.3,
 * `Checks\AuthenticationConfigurationCheck`).
 *
 * It hands over the closures of its `checks()` that concern
 * `laravel-authentication`: those about no one guard, and those about a guard
 * by name, so `authentication:check` reports each under the guard it is about
 * and `--guard` limits them. Each closure is one `checks()` holds too, built
 * the same way and graded the same way: one that throws is a problem, one that
 * returns a note is something to report without failing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface AuthenticationCheck extends Check
{
    /**
     * The checks of `laravel-authentication`'s side about no one guard.
     *
     * @return list<\Closure(): mixed>
     */
    public function authenticationChecks(): array;

    /**
     * The checks of `laravel-authentication`'s side about the guard; none when
     * nothing the check covers names it.
     *
     * @param  string  $guard
     * @return list<\Closure(): mixed>
     */
    public function guardChecks(string $guard): array;
}
