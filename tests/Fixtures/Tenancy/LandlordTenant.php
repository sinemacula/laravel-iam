<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * A tenant kept apart from the storage connection, on a landlord connection
 * that reads from a replica and writes to its primary, identified by its key.
 *
 * The test that uses it configures the connection, so a replica that has not
 * yet seen a tenant the primary holds can be read.
 *
 * @property string $id
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LandlordTenant extends Model implements Tenant
{
    /** @var string The connection the tenants are kept on. */
    public const string CONNECTION = 'landlord';

    /** @var string The table the tenants are kept in. */
    public const string TABLE = 'iam_landlord_tenants';

    /** @var bool Whether the key increments: it is the tenant's opaque id. */
    public $incrementing = false;

    /** @var bool Whether the tenants are timestamped: they are not. */
    public $timestamps = false;

    /** @var string|\UnitEnum|null The connection the tenants are kept on. */
    protected $connection = self::CONNECTION;

    /** @var ?string The table the tenants are kept in. */
    protected $table = self::TABLE;

    /** @var string The key's type: the tenant's opaque id. */
    protected $keyType = 'string';

    /**
     * The tenant's opaque id: its key.
     *
     * @return mixed
     */
    #[\Override]
    public function getTenantIdentifier(): mixed
    {
        return $this->getKey();
    }
}
