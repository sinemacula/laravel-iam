<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * A person whose seats are archived (`ArchivedSeat`).
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
final class ArchivingSeatHolder extends User implements HasPrincipals, Identity
{
    /** @var ?string The table the people are kept in. */
    protected $table = 'iam_people';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['name', 'email'];

    /**
     * The seats the person holds, an archived one hidden.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function principals(): Builder
    {
        return $this->hasMany(ArchivedSeat::class, 'person_id');
    }

    /**
     * The person's default principal: none.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolveDefaultPrincipal(): ?Principal
    {
        return null;
    }
}
