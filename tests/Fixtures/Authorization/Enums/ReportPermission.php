<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization\Enums;

use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

/**
 * Report permissions and the API access permission.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum ReportPermission: string implements PermissionEnum
{
    case READ   = 'reports:read';
    case EXPORT = 'reports:export';
    case DELETE = 'reports:delete';
    case USE    = 'api:use';
}
