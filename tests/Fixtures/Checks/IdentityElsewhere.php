<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Checks;

use Illuminate\Database\Eloquent\Model;

/**
 * An identity model on another connection than the shared one.
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
