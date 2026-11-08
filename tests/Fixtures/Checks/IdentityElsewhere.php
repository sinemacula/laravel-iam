<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Checks;

use Illuminate\Database\Eloquent\Model;

/**
 * An identity model that lives on another connection than the shared storage
 * connection, which IAM-2.3 forbids and `iam:check` reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IdentityElsewhere extends Model
{
    /** @var string|\UnitEnum|null The connection the model lives on. */
    protected $connection = 'elsewhere';
}
