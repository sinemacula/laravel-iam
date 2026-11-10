<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Contracts;

use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * The application's opt-in re-sync of an identity provider's groups at a later
 * sign-in (IAM-7.2): what a person who signs in again through a connection, now
 * reported in these groups, holds because of them.
 *
 * SSO reports the groups on every verified result but changes nothing with
 * them, so a person's grants follow a change of their groups at the provider
 * only where the application asks for it. With one configured, this package's
 * sign-in redemption (`Iam::signIns()->redeem()`) calls it for every `sign_in`
 * SSO redeemed that links an identity and signs it in, once the redemption's
 * transaction has committed, in a transaction of its own on the storage
 * connection, retried whole after a concurrency failure, and before the
 * credential is handed out. It never runs under SSO's redemption locks: a grant
 * that widens the identity's scope reports it to SSO first
 * (`Authorization\GrantHookAdapter`), which takes SSO's identity guard, and
 * SSO's lock order puts that guard before the connections the redemption
 * locked. A re-sync that throws rolls its own transaction back, nothing granted
 * or revoked, and refuses the sign-in once it has committed: the code is spent
 * and the session written is never handed out. It is not called for a sign-in
 * SSO refused. The first sign-in of a person just provisioned is re-synced too,
 * with the groups the provisioning mapped, so it changes nothing there.
 *
 * `Provisioning\MappedGroupResync` makes the identity's own roles in the
 * connection's tenant exactly those the group mapping now answers, granting
 * what is new and revoking what is no longer mapped; implement this to keep
 * whatever else the application's rules say. Write every row on the storage
 * connection, through `laravel-authorization`'s services, which run in the
 * re-sync's transaction; take no lock on rows other writers share before them.
 * Throw to refuse.
 *
 * Name the implementation in `iam.provisioning.groups.resync`, or bind it in
 * the container; with neither, nothing is re-synced.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
interface GroupResync
{
    /**
     * Bring what the identity holds because of its provider groups into line
     * with the groups now reported through the connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  list<string>  $groups
     * @return void
     *
     * @throws \Throwable
     */
    public function resync(Identity $identity, string $connectionId, string $tenantId, array $groups): void;
}
