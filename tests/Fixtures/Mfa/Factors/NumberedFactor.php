<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\Factors;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * An application's factor model whose identifier is a number, as one keyed by
 * an auto-incrementing integer is: a proof made with it names it as text, so
 * the proof store must match the two as text.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NumberedFactor extends Factor
{
    /** @var int The number every factor of this model is identified by. */
    public const int NUMBER = 42;

    /**
     * The factor's identifier: a number.
     *
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return self::NUMBER;
    }
}
