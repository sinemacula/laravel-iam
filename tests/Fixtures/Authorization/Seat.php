<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * A principal kept apart from the person who acts as it, as a membership
 * principal an application keeps for each tenant a person belongs to:
 * `laravel-authentication`'s principal, a model of its own, owned by a person
 * who is an identity alone (`Staff`), and acting in the organisation it names,
 * or in none.
 *
 * It is kept in the fixtures' memberships table, on the default connection, the
 * tests' shared storage connection.
 *
 * @property int $id
 * @property int $person_id
 * @property ?string $tenant_id
 * @property \Tests\Fixtures\Authorization\Staff $person
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Seat extends Model implements Principal
{
    /** @var ?string The table seats are kept in. */
    protected $table = 'iam_memberships';

    /** @var list<string> The attributes a test may fill. */
    protected $fillable = ['person_id', 'tenant_id'];

    /**
     * The seat's own id, as text.
     *
     * @return string
     */
    #[\Override]
    public function getPrincipalIdentifier(): string
    {
        return (string) $this->id;
    }

    /**
     * The person who holds the seat.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    #[\Override]
    public function getIdentity(): Identity
    {
        return $this->person;
    }

    /**
     * The organisation the seat acts in, or `null` for none.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    public function getTenant(): ?Tenant
    {
        return $this->tenant_id === null ? null : new Organisation($this->tenant_id);
    }

    /**
     * The person who holds the seat.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Fixtures\Authorization\Staff, $this>
     */
    public function person(): BelongsTo
    {
        return $this->belongsTo(Staff::class, 'person_id');
    }
}
