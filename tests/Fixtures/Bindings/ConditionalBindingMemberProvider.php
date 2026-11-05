<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Support\ServiceProvider;
use Tests\Fixtures\Bindings\Contracts\ClosureSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;

/**
 * A member's provider that binds its defaults only where nothing is bound yet,
 * as laravel-authentication and laravel-audit-log do: one with `singletonIf()`
 * of a class name, and one with `bindIf()` of a closure the provider declares.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConditionalBindingMemberProvider extends ServiceProvider
{
    /**
     * Bind the member's defaults.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->singletonIf(SharedSeam::class, MemberDefault::class);
        $this->app->bindIf(ClosureSeam::class, static fn (): MemberDefault => new MemberDefault);
    }
}
