<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A tenant tree an application names in `authorization.tenant_tree`, or binds
 * on `laravel-authorization`'s contract itself, in place of this package's: a
 * flat one, as `laravel-authorization`'s own default answers, under a class of
 * the application's, so a test can tell it from both.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class NamedTenantTree implements TenantTree
{
    /**
     * No ancestors.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function ancestors(Reference $tenant): array
    {
        return [];
    }

    /**
     * Whether the tenant is the other.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    #[\Override]
    public function isWithin(Reference $tenant, Reference $ancestor): bool
    {
        return (new FlatTenantTree)->isWithin($tenant, $ancestor);
    }

    /**
     * The tenant alone.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        return (new FlatTenantTree)->subtree($tenant);
    }
}
