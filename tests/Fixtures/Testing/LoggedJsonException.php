<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

/**
 * An exception a gateway might log or throw that gives the log its JSON form,
 * as a provider's error might, or refuses to, as a `Secret` does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LoggedJsonException extends \RuntimeException implements \JsonSerializable
{
    /** @var string The JSON form that makes the exception refuse to give one. */
    public const string REFUSE = 'refuse';

    /** @var mixed The JSON form the exception gives, or `REFUSE`. */
    private readonly mixed $json;

    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  mixed  $json
     * @param  ?\Throwable  $previous
     */
    public function __construct(string $message, mixed $json, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);

        $this->json = $json;
    }

    /**
     * The exception's JSON form, unless it refuses to give one.
     *
     * @return mixed
     *
     * @throws \LogicException
     */
    #[\Override]
    public function jsonSerialize(): mixed
    {
        return $this->json === self::REFUSE ? throw new \LogicException('The exception refuses to be encoded.') : $this->json;
    }
}
