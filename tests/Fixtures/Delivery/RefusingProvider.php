<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Delivery;

/**
 * A provider's client that refuses every message it is given, with an exception
 * that names nothing of it, so whatever a gateway passes it is left only in the
 * exception's stack trace, as the arguments of its frame.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefusingProvider
{
    /** @var string What the provider's exception says. */
    public const string REFUSED = 'The provider refused the message.';

    /**
     * Refuse the message.
     *
     * @param  string  ...$arguments
     * @return never
     *
     * @throws \RuntimeException
     */
    public static function send(string ...$arguments): never
    {
        throw new \RuntimeException(self::REFUSED);
    }
}
