<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Checks;

use SineMacula\Laravel\Iam\Checks\Contracts\AuthenticationCheck;

/**
 * A check that answers as the test scripts it: whether it applies, and the
 * closures it hands back, or what building them throws, about no one guard and
 * about each guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ScriptedCheck implements AuthenticationCheck
{
    /**
     * Constructor.
     *
     * @param  string  $subject
     * @param  list<\Closure(): mixed>  $checks
     * @param  bool  $applies
     * @param  ?\Throwable  $failure
     * @param  array<string, list<\Closure(): mixed>>  $guardChecks
     */
    public function __construct(

        /** The subject the check reports under. */
        private string $subject,

        /** The closures the check hands back. */
        private array $checks = [],

        /** Whether the check applies. */
        private bool $applies = true,

        /** What building the closures throws, if anything. */
        private ?\Throwable $failure = null,

        /** The closures the check hands back about each guard, by name. */
        private array $guardChecks = [],
    ) {}

    /**
     * The subject the check reports under.
     *
     * @return string
     */
    #[\Override]
    public function subject(): string
    {
        return $this->subject;
    }

    /**
     * Whether the check applies.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return $this->applies;
    }

    /**
     * The closures, or what building them throws.
     *
     * @return list<\Closure(): mixed>
     *
     * @throws \Throwable
     */
    #[\Override]
    public function checks(): array
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->checks;
    }

    /**
     * The closures about no one guard, those `checks()` hands back.
     *
     * @return list<\Closure(): mixed>
     *
     * @throws \Throwable
     */
    #[\Override]
    public function authenticationChecks(): array
    {
        return $this->checks();
    }

    /**
     * The closures about the guard.
     *
     * @param  string  $guard
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function guardChecks(string $guard): array
    {
        return $this->guardChecks[$guard] ?? [];
    }
}
