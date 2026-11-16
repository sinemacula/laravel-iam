<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * A person on the people table who can be soft-deleted and restored.
 *
 * @property int $id
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DepartingPerson extends User implements Identity
{
    use SoftDeletes;

    /** @var ?string The table people are kept in. */
    protected $table = 'iam_people';
}
