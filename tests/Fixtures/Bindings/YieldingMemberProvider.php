<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Support\ServiceProvider;
use Tests\Fixtures\Bindings\Contracts\FeatureSeam;
use Tests\Fixtures\Bindings\Contracts\ScopedSeam;
use Tests\Fixtures\Bindings\Contracts\TransientSeam;

/**
 * A member's provider that binds its defaults with `bindIf()`, only where
 * nothing is bound yet, as laravel-mfa and laravel-sso do.
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
        $this->app->bindIf(TransientSeam::class, MemberDefault::build(...));
        $this->app->bindIf(ScopedSeam::class, MemberDefault::build(...));
        $this->app->bindIf(FeatureSeam::class, MemberDefault::build(...));
    }
}
