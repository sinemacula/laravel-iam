<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * A person as an identity alone, in an application whose principals are kept
 * apart from the people who act as them: `laravel-authentication`'s identity
 * and `laravel-authorization`'s, holding grants of its own (a platform staff
 * flag held by the person, say), but no principal itself.
 *
 * It is kept in the fixtures' people table, on the default connection, the
 * tests' shared storage connection.
 *
 * @property int $id
 * @property string $name
 * @property string $email
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Staff extends User implements AuthorizableIdentity, Identity
{
    use HasAuthorization;

    /** @var ?string The table the people are kept in. */
    protected $table = 'iam_people';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['name', 'email'];
}
