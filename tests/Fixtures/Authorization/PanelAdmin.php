<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * An admin panel user with grants who is not an authentication identity.
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
