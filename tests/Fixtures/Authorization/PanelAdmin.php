<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * The user of an admin panel on a Laravel session guard: an Eloquent user that
 * holds `laravel-authorization`'s grants of its own, but is not
 * `laravel-authentication`'s identity, so SSO never links it.
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
final class PanelAdmin extends User implements AuthorizableIdentity
{
    use HasAuthorization;

    /** @var ?string The table the people are kept in. */
    protected $table = 'iam_people';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['name', 'email'];
}
