<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Support\ServiceProvider;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;

/**
 * A member's provider that binds its default with a plain `bind()`, replacing
 * whatever was bound before it, as laravel-mfa did before laravel-mfa#92 and
 * laravel-authorization still binds its resolvers (IAM-13.7). Registered after
 * this package, it replaces the adapter: that is the member's defect, which
 * this package does not work around.
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
        $this->app->bind(PlainSeam::class, MemberDefault::build(...));
    }
}
