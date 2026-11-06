<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

/**
 * An object a gateway might log that the log writes by its public properties,
 * as a provider's request object, holding a private one the log never reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LoggedProperties
{
    /**
     * Constructor.
     *
     * @param  mixed  $public
     * @param  string  $hidden
     */
    public function __construct(

        /** A property anything may read. */
        public mixed $public,

        /** A property only the object reads. */
        private string $hidden = 'hidden-value',
    ) {}

    /**
     * The property only the object reads.
     *
     * @return string
     */
    public function hidden(): string
    {
        return $this->hidden;
    }
}
