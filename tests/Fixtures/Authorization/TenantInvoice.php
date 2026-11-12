<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * A tenant-scoped application record kept on its own connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TenantInvoice extends Model implements QueryableResource
{
    /** @var string The name of the connection the invoices are kept on. */
    public const string CONNECTION = 'invoices';

    /** @var string The invoices' table. */
    public const string TABLE = 'iam_tenant_invoices';

    /** @var bool Whether the model keeps timestamps. */
    public $timestamps = false;

    /** @var string|\UnitEnum|null The connection the invoices are kept on. */
    protected $connection = self::CONNECTION;

    /** @var array<string> The attributes that are not mass assignable. */
    protected $guarded = [];

    /** @var ?string The table the invoices are kept in. */
    protected $table = self::TABLE;

    /**
     * The invoice's tenant, named in its `tenant_type` and `tenant_id` columns.
     *
     * @return \SineMacula\Laravel\Authorization\Support\ResourceTenancy
     */
    #[\Override]
    public static function resourceTenancy(): ResourceTenancy
    {
        return ResourceTenancy::columns();
    }
}
