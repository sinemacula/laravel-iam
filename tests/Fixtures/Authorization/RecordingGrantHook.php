<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;

/**
 * A grant hook that allows every grant and records each widening.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingGrantHook implements GrantHook
{
    /** @var list<\SineMacula\Laravel\Authorization\Hooks\GrantWidening> The widenings handed over, in order. */
    public array $widenings = [];

    /**
     * Record the widening, and let the grant go on.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     */
    #[\Override]
    public function beforeWidening(GrantWidening $widening): void
    {
        $this->widenings[] = $widening;
    }
}
