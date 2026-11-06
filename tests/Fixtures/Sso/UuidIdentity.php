<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * An Eloquent identity keyed by a UUID it generates, written in lower case.
 *
 * Its table is created by the test that needs it, with the key a `uuid` column:
 * PostgreSQL's `uuid` type and a MySQL `_ci` collation both match the same UUID
 * written in upper case, and on SQLite the key is compared case-insensitively,
 * so a reference naming it in upper case finds it on every engine.
 *
 * @property string $id
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UuidIdentity extends User implements Identity
{
    use HasUuids;

    /** @var string The table the identities are kept in. */
    public const string TABLE = 'iam_uuid_identities';

    /** @var ?string The table the identities are kept in. */
    protected $table = self::TABLE;
}
