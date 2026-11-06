<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Models;

use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * A machine: an API client or a service account, declared as
 * `laravel-authentication`'s machine identity on its own class.
 *
 * It is MFA's identity too, through MFA's own trait, whose defaults say every
 * identity may hold factors and is active, as an application's machine model
 * would say until it is told otherwise: so only the machine identity contract
 * tells it apart from a person, which is what this package reads (IAM-3.12). It
 * lives on the default connection, the tests' shared storage connection.
 *
 * @property int $id
 * @property string $name
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Machine extends User implements MachineIdentity, MultiFactorAuthenticatable
{
    use HasFactors;

    /** @var ?string The table machines are kept in. */
    protected $table = 'iam_machines';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['name'];
}
