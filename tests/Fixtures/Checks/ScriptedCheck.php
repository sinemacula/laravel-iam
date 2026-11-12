<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Checks;

use SineMacula\Laravel\Iam\Checks\Contracts\Check;

/**
 * A check that applies, returns closures or throws as the test scripts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ScriptedCheck implements Check
{
    /**
     * Constructor.
     *
     * @param  string  $subject
     * @param  list<\Closure(): mixed>  $checks
     * @param  bool  $applies
     * @param  ?\Throwable  $failure
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
}
