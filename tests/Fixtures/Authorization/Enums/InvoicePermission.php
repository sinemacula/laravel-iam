<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization\Enums;

use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

/**
 * The permissions an application declares for its invoices, which a policy
 * allows once the session is authenticated strongly enough.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum InvoicePermission: string implements PermissionEnum
{
    case REFUND = 'invoices:refund';
    case VOID   = 'invoices:void';
}
