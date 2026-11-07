<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;

/**
 * An application's own provider that binds its memberships and its tenant tree
 * from its `register()`, as an application's `AppServiceProvider` does, which
 * Laravel registers after every package provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BindsTenancyWhileRegistering extends ServiceProvider
{
    /**
     * Bind the application's memberships and tenant tree.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->singleton(Memberships::class, static fn (): FakeMemberships => new FakeMemberships);
        $this->app->singleton(TenantTree::class, static fn (): FakeTenantTree => new FakeTenantTree);
    }
}
