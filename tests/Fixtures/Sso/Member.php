<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Casts\NormalizedIdentifier;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * An identity of a second kind, with no unique index on its verified email
 * address.
 *
 * @property int $id
 * @property string $email
 * @property ?\Illuminate\Support\Carbon $email_verified_at
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Member extends User implements HasVerifiableIdentifiers, Identity
{
    use ProvidesIdentifierVerification;

    /** @var string The table members are kept in. */
    public const string TABLE = 'iam_members';

    /** @var ?string The table members are kept in. */
    protected $table = self::TABLE;

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['email', 'email_verified_at'];

    /**
     * The email address in its normal form, and when it was verified.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'email'             => NormalizedIdentifier::using('email'),
            'email_verified_at' => 'datetime',
        ];
    }
}
