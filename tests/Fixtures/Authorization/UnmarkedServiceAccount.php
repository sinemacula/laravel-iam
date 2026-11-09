<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * A service account an application has not marked as `laravel-authorization`'s
 * machine: `laravel-authentication`'s machine identity and its principal in one
 * model, as `ServiceAccount` is, without `AuthorizableMachine`, so only the
 * session policy source stands between its grants and every check.
 *
 * It lives in the fixtures' machines table, beside `ServiceAccount`.
 *
 * @property int $id
 * @property string $name
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnmarkedServiceAccount extends User implements AuthorizableIdentity, MachineIdentity, Principal
{
    use ActsAsPrincipal, HasAuthorization;

    /** @var ?string The table service accounts are kept in. */
    protected $table = 'iam_machines';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['name'];
}
