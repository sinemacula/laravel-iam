<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * A person who owns principals of their own, a seat for each tenant they belong
 * to (`Seat`), as an application that keeps its principals apart from its
 * people lists them: `laravel-authentication`'s identity owning principals,
 * whose `principals()` relation lists every seat it holds.
 *
 * It is kept in the fixtures' people table, on the default connection, the
 * tests' shared storage connection.
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
final class SeatHolder extends User implements HasPrincipals, Identity
{
    /** @var ?string The table the people are kept in. */
    protected $table = 'iam_people';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['name', 'email'];

    /**
     * Every seat the person holds.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function principals(): Builder
    {
        return $this->hasMany(Seat::class, 'person_id');
    }

    /**
     * No seat is the person's default.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolveDefaultPrincipal(): ?Principal
    {
        return null;
    }
}
