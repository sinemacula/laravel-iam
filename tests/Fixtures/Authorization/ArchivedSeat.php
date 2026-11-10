<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * A principal an application archives rather than deletes: a seat as `Seat`
 * keeps it, but soft-deleted, so the model's global scope hides an archived
 * seat from every query, its grants kept for when it is restored.
 *
 * It is kept in the fixtures' memberships table, its archive time in the
 * `accepted_at` column, which the table already has, on the default connection,
 * the tests' shared storage connection.
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
final class ArchivedSeat extends Model implements Principal
{
    use SoftDeletes;

    /** @var string The column a seat's archive time is kept in. */
    public const string DELETED_AT = 'accepted_at';

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
