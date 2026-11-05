<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Support\ServiceProvider;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;

/**
 * A member's provider that binds its default with a plain `bind()` of a class
 * name, as laravel-mfa did before laravel-mfa#90 and as any provider may,
 * replacing whatever was bound before it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PlainBindingMemberProvider extends ServiceProvider
{
    /**
     * Bind the member's default.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->bind(PlainSeam::class, MemberDefault::class);
    }
}
