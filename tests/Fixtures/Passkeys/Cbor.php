<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Passkeys;

/**
 * The subset of CBOR (RFC 8949) an authenticator writes: integers, byte
 * strings, text strings and maps, in definite lengths. Strings are byte strings
 * unless wrapped with `text()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Cbor
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Mark a string to be encoded as a text string rather than bytes.
     *
     * @param  string  $value
     * @return \Stringable
     */
    public static function text(string $value): \Stringable
    {
        return new class ($value) implements \Stringable {
            /**
             * Constructor.
             *
             * @param  string  $value
             */
            public function __construct(

                /** The text to encode. */
                private readonly string $value,
            ) {}

            /**
             * The text.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return $this->value;
            }
        };
    }

    /**
     * Encode the value: an integer, a byte string, a text string, or a map
     * given as a list of `[key, value]` pairs, so keys keep their order and
     * type. A map's values are encoded the same way, so maps nest.
     *
     * @param  mixed  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function encode(mixed $value): string
    {
        return match (true) {
            is_int($value)                => $value >= 0 ? self::head(0, $value) : self::head(1, -1 - $value),
            is_string($value)             => self::head(2, strlen($value)) . $value,
            $value instanceof \Stringable => self::head(3, strlen((string) $value)) . $value,
            is_array($value)              => self::map($value),
            default                       => throw new \InvalidArgumentException('CBOR encodes an integer, a byte or text string, or a map alone.'),
        };
    }

    /**
     * Encode a map of `[key, value]` pairs.
     *
     * @param  array<array-key, mixed>  $pairs
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function map(array $pairs): string
    {
        $encoded = self::head(5, count($pairs));

        foreach ($pairs as $pair) {

            if (!is_array($pair) || !array_key_exists(0, $pair) || !array_key_exists(1, $pair)) {
                throw new \InvalidArgumentException('A CBOR map is given as [key, value] pairs.');
            }

            $encoded .= self::encode($pair[0]) . self::encode($pair[1]);
        }

        return $encoded;
    }

    /**
     * Encode a major type and its argument.
     *
     * @param  int  $major
     * @param  int  $argument
     * @return string
     */
    private static function head(int $major, int $argument): string
    {
        return match (true) {
            $argument < 24      => chr(($major << 5) | $argument),
            $argument < 0x100   => chr(($major << 5) | 24) . chr($argument),
            $argument < 0x10000 => chr(($major << 5) | 25) . pack('n', $argument),
            default             => chr(($major << 5) | 26) . pack('N', $argument),
        };
    }
}
