<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\Pending;

use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Casts\NormalizedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * A person `laravel-authentication` signs in who is no identity of MFA's: one
 * holding no factors, so a pending session of theirs names no one MFA could
 * verify a further factor for.
 *
 * It reads the fixtures' people table, so a person created there signs in as a
 * stranger too, on a guard over this model.
 *
 * @property int $id
 * @property string $email
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Stranger extends User implements HasSessions, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var ?string The table people are kept in. */
    protected $table = 'iam_people';

    /** @var list<string> The attributes never serialised. */
    protected $hidden = ['password'];

    /**
     * The stranger's sessions, of `laravel-authentication`'s session model.
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
