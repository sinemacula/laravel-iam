<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

/**
 * An object a gateway might log that gives the log its string, as a provider's
 * response does its body, or refuses to, while holding a public property of its
 * own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LoggedString implements \Stringable
{
    /** @var string The string that makes the object refuse to give one. */
    public const string REFUSE = 'refuse';

    /**
     * Constructor.
     *
     * @param  string  $string
     * @param  ?string  $public
     */
    public function __construct(

        /** The string the object gives, or `REFUSE`. */
        private string $string,

        /** A property anything may read. */
        public ?string $public = null,
    ) {}

    /**
     * The object's string, unless it refuses to give one.
     *
     * @return string
     *
     * @throws \LogicException
     */
    #[\Override]
    public function __toString(): string
    {
        return $this->string === self::REFUSE ? throw new \LogicException('The object refuses to be cast.') : $this->string;
    }
}
