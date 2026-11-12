<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * An Eloquent identity keyed by a string handle, compared case-insensitively on
 * SQLite.
 *
 * @property string $id
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class HandledIdentity extends User implements Identity
{
    /** @var string The table the identities are kept in. */
    public const string TABLE = 'iam_handled_identities';

    /** @var bool Whether the key increments: it is the handle given. */
    public $incrementing = false;

    /** @var ?string The table the identities are kept in. */
    protected $table = self::TABLE;

    /** @var string The key's type: a handle. */
    protected $keyType = 'string';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['id'];
}
