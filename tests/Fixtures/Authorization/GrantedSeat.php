<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;

/**
 * A seat that holds grants of its own.
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
final class GrantedSeat extends Model implements Principal, SupportsPermissions, SupportsPolicies, SupportsRoles
{
    use HasAuthorization;

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
