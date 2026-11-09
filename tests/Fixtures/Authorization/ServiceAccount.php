<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine;

/**
 * A service account: `laravel-authentication`'s machine identity and its
 * principal in one model, authenticating with an API key, and
 * `laravel-authorization`'s machine principal, whose grants count only within
 * the scopes of the credential it acts with.
 *
 * It lives in the fixtures' machines table, on the default connection, the
 * tests' shared storage connection.
 *
 * @property int $id
 * @property string $name
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ServiceAccount extends User implements AuthorizableIdentity, AuthorizableMachine, MachineIdentity, Principal
{
    use ActsAsPrincipal, HasAuthorization;

    /** @var ?string The table service accounts are kept in. */
    protected $table = 'iam_machines';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['name'];
}
