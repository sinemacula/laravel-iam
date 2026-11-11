<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks\Contracts;

/**
 * One of this package's own checks, which `iam:check` runs after the members'.
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
