<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Models;

use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Casts\NormalizedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * A person who signs in and acts as themselves: `laravel-authentication`'s
 * identity and principal in one model (its two-dimensional adoption), with
 * sessions, and MFA's identity, with factors.
 *
 * It lives on the default connection, which the tests keep as the shared
 * storage connection with every member's tables, as IAM-2.3 asks of an
 * application's identity models, and signs in with its email address and
 * password.
 *
 * @property int $id
 * @property string $name
 * @property string $email
 * @property ?string $password
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Person extends User implements HasSessions, Identity, MultiFactorAuthenticatable, Principal
{
    use ActsAsPrincipal, Authenticatable, HasFactors;

    /** @var ?string The table people are kept in. */
    protected $table = 'iam_people';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['name', 'email', 'password'];

    /** @var list<string> The attributes never serialised. */
    protected $hidden = ['password'];

    /**
     * The person's sessions, of `laravel-authentication`'s session model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\SineMacula\Laravel\Authentication\Models\Session, $this>
     */
    #[\Override]
    public function sessions(): MorphMany
    {
        return $this->morphMany(Session::class, 'authenticatable');
    }

    /**
     * The attributes cast on read and write: the email address, an identifier
     * kept in its normal form, and the password, hashed.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'email'    => NormalizedIdentifier::using('email'),
            'password' => 'hashed',
        ];
    }
}
