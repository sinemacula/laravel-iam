<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use Illuminate\Database\Eloquent\Model;

/**
 * A stored membership of a tenant, or a platform principal.
 *
 * @property int $id
 * @property int $person_id
 * @property ?string $tenant_id
 * @property ?\Carbon\CarbonImmutable $accepted_at
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StoredMembership extends Model
{
    /** @var ?string The table memberships are kept in. */
    protected $table = 'iam_memberships';

    /** @var list<string> The attributes the tests fill. */
    protected $fillable = ['person_id', 'tenant_id', 'accepted_at'];

    /**
     * The attributes cast, the acceptance time as an immutable instant.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return ['accepted_at' => 'immutable_datetime'];
    }
}
