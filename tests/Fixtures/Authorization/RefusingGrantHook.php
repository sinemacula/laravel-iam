<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;

/**
 * A grant hook an application lists in `authorization.grant_hooks` that refuses
 * every widening it is handed, as an application's own veto does, so a test can
 * show that a refusal after SSO's widening rolls the whole grant back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefusingGrantHook implements GrantHook
{
    /** @var string The message every refusal carries. */
    public const string MESSAGE = 'The application refuses the grant.';

    /**
     * Refuse the widening.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     *
     * @throws \RuntimeException
     *
     * @SuppressWarnings("php:S1172")
     */
    #[\Override]
    public function beforeWidening(GrantWidening $widening): void
    {
        throw new \RuntimeException(self::MESSAGE);
    }
}
