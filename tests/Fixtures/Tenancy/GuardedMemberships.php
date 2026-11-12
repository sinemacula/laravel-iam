<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Tenancy\MembershipSet;

/**
 * Memberships read under a shared lock that revoking waits on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GuardedMemberships implements Memberships
{
    /**
     * The person's memberships, guarded until the asking transaction ends.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Iam\Tenancy\MembershipSet
     */
    #[\Override]
    public function of(Identity $identity): MembershipSet
    {
        $rows = StoredMembership::query()
            ->useWritePdo()
            ->where('person_id', $identity->getAuthIdentifier())
            ->sharedLock()
            ->get();

        return new MembershipSet(array_values($rows->map(static fn (StoredMembership $row): Membership => self::membershipOf($row))->all()), true);
    }

    /**
     * Revoke the membership by deleting its row, returning the rows deleted.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @param  ?string  $connection
     * @return int
     */
    public static function revoke(Identity $identity, string $tenantId, ?string $connection = null): int
    {
        return StoredMembership::on($connection)->where('person_id', $identity->getAuthIdentifier())->where('tenant_id', $tenantId)->toBase()->delete();
    }

    /**
     * The membership the row stores.
     *
     * @param  \Tests\Fixtures\Tenancy\StoredMembership  $row
     * @return \SineMacula\Laravel\Iam\Tenancy\Membership
     */
    private static function membershipOf(StoredMembership $row): Membership
    {
        return $row->tenant_id === null ? Membership::platform($row->accepted_at) : Membership::of($row->tenant_id, $row->accepted_at);
    }
}
