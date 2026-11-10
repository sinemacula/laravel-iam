<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * An application's own resource tenant resolver, which answers no record's
 * tenant: only its being the application's, not its answers, is what a test
 * reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OwnResourceTenants implements ResourceTenantResolver
{
    /**
     * The tenant of the model: none.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $resource
     * @return ?\SineMacula\Laravel\Authorization\Support\Reference
     */
    #[\Override]
    public function tenantOf(Model $resource): ?Reference
    {
        return null;
    }

    /**
     * The tenant of the record: none.
     *
     * @param  string  $type
     * @param  string  $id
     * @return false|\SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function tenantOfRecord(string $type, string $id): false|Reference|null
    {
        return null;
    }
}
