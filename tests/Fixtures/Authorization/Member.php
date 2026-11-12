<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Casts\NormalizedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * A person who signs in as themselves and holds authorization grants.
 *
 * @property int $id
 * @property string $name
 * @property string $email
 * @property ?string $password
 * @property bool $is_active
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Member extends User implements AuthorizableIdentity, CanBeActive, HasSessions, Identity, MultiFactorAuthenticatable, Principal
{
    use ActsAsPrincipal, Authenticatable, HasAuthorization, HasFactors, ProvidesActiveState;

    /** @var ?string The table members are kept in. */
    protected $table = 'iam_people';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['name', 'email', 'password', 'is_active'];

    /** @var array<string, mixed> The attributes' values before anything is set: a new member is active. */
    protected $attributes = ['is_active' => true];

    /** @var list<string> The attributes never serialised. */
    protected $hidden = ['password'];

    /**
     * The member's sessions, of `laravel-authentication`'s session model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\SineMacula\Laravel\Authentication\Models\Session, $this>
     */
    #[\Override]
    public function sessions(): MorphMany
    {
        return $this->morphMany(Session::class, 'authenticatable');
    }

    /**
     * The attributes cast on read and write.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'email'     => NormalizedIdentifier::using('email'),
            'password'  => 'hashed',
            'is_active' => 'boolean',
        ];
    }
}
