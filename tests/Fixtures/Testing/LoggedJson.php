<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

/**
 * An object a gateway might log that gives the log its JSON form, or refuses
 * to, as a `Secret` does, while holding a public property of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LoggedJson implements \JsonSerializable
{
    /** @var string The JSON form that makes the object refuse to give one. */
    public const string REFUSE = 'refuse';

    /**
     * Constructor.
     *
     * @param  mixed  $json
     * @param  ?string  $public
     */
    public function __construct(

        /** The JSON form the object gives, or `REFUSE`. */
        private mixed $json,

        /** A property anything may read. */
        public ?string $public = null,
    ) {}

    /**
     * The object's JSON form, unless it refuses to give one.
     *
     * @return mixed
     *
     * @throws \LogicException
     */
    #[\Override]
    public function jsonSerialize(): mixed
    {
        return $this->json === self::REFUSE ? throw new \LogicException('The object refuses to be encoded.') : $this->json;
    }
}
