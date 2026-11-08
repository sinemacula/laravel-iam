<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;

/**
 * An application's provider that turns on, from its `register()`, the hand-off
 * of a sign-in that resolves to no identity for SSO's `api` application, which
 * this package's bridge check refuses while SSO is in use, wherever a test puts
 * it in the provider order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class HandsOffUnlinkedSignInsWhileRegistering extends ServiceProvider
{
    /** @var string The setting turned on. */
    public const string KEY = 'sso.applications.api.unlinked_handoffs';

    /**
     * Turn the hand-off of unlinked sign-ins on.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        Config::set(self::KEY, true);
    }
}
