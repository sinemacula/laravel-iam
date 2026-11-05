<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Support\ServiceProvider;
use Tests\Fixtures\Bindings\Contracts\FeatureSeam;
use Tests\Fixtures\Bindings\Contracts\ScopedSeam;
use Tests\Fixtures\Bindings\Contracts\TransientSeam;

/**
 * A member's provider that binds its defaults only where nothing is bound yet:
 * two with `bindIf()` of a class name, as laravel-mfa binds its defaults since
 * laravel-mfa#92, and one with `scopedIf()`, as laravel-sso binds its
 * request-scoped ones.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class YieldingMemberProvider extends ServiceProvider
{
    /**
     * Bind the member's defaults.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->bindIf(TransientSeam::class, MemberDefault::class);
        $this->app->scopedIf(ScopedSeam::class, MemberDefault::class);
        $this->app->bindIf(FeatureSeam::class, MemberDefault::class);
    }
}
