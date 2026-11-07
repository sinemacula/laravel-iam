<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use SineMacula\Laravel\Authentication\Contracts\IdentifierNormalizer;

/**
 * An email normaliser that trims an address and keeps its case.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeepsCase implements IdentifierNormalizer
{
    /**
     * The address trimmed, or `null` when nothing is left.
     *
     * @param  string  $identifier
     * @return ?string
     */
    #[\Override]
    public function normalize(#[\SensitiveParameter] string $identifier): ?string
    {
        $trimmed = trim($identifier);

        return $trimmed === '' ? null : $trimmed;
    }
}
