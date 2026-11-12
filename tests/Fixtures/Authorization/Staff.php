<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * A person who is an identity and grantee but no principal.
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
