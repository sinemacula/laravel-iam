<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * An Eloquent identity keyed by a lower-case UUID it generates.
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
