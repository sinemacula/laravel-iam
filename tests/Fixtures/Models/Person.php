<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Models;

use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Casts\NormalizedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Iam\Concerns\MfaActiveFromAuthentication;
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
 * password. It is active until a test clears its `is_active` flag, which
 * `laravel-authentication` reads as its active state, and MFA reads the same
 * through `MfaActiveFromAuthentication`; its phone number, when it has one, is
 * kept in its normal form; and each identifier is verified once its
 * `<type>_verified_at` column is set, so a verified one can sign in by code.
 *
 * @property int $id
 * @property string $name
 * @property string $email
 * @property ?string $phone
 * @property ?string $password
 * @property bool $is_active
 * @property ?\Illuminate\Support\Carbon $email_verified_at
 * @property ?\Illuminate\Support\Carbon $phone_verified_at
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Person extends User implements CanBeActive, HasSessions, HasVerifiableIdentifiers, Identity, MultiFactorAuthenticatable, Principal
{
    use ActsAsPrincipal, Authenticatable, HasFactors, MfaActiveFromAuthentication, ProvidesActiveState, ProvidesIdentifierVerification {
        MfaActiveFromAuthentication::isMfaActive insteadof HasFactors;
    }

    /** @var ?string The table people are kept in. */
    protected $table = 'iam_people';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['name', 'email', 'phone', 'password', 'is_active', 'email_verified_at', 'phone_verified_at'];

    /** @var array<string, mixed> The attributes' values before anything is set: a new person is active. */
    protected $attributes = ['is_active' => true];

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
     * The attributes cast on read and write: the email address and the phone
     * number, identifiers kept in their normal form, the password, hashed, the
     * active flag, and when each identifier was verified.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'email'             => NormalizedIdentifier::using('email'),
            'phone'             => NormalizedIdentifier::using('phone'),
            'password'          => 'hashed',
            'is_active'         => 'boolean',
            'email_verified_at' => 'datetime',
            'phone_verified_at' => 'datetime',
        ];
    }
}
