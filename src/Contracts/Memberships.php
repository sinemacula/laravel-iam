<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Contracts;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Tenancy\MembershipSet;

/**
 * Memberships contract: the application's one answer for which tenants an
 * identity is a current member of, and when the person accepted each (IAM-7.4).
 *
 * Memberships are the application's own data. The application implements this
 * once and binds it in a service provider's `register()` (one bound from a
 * `boot()` leaves SSO's refusing defaults bound), and the package answers SSO's
 * tenant membership, its link eligibility and the membership half of its
 * principal scope from it, so none of them disagrees with another about a
 * person, and none is answered by `laravel-authorization`.
 *
 * Answer every current membership, a platform principal among them (a
 * membership of no tenant), each with the time the person accepted it: never a
 * time an administrator created or imported it, and none for an invitation not
 * taken up. A set that cannot be read completely (a store that answers in part,
 * a principal kept elsewhere that cannot be reached) is answered marked
 * incomplete, never as though it were complete. A membership revoked or expired
 * is no current membership. A read that fails throws.
 *
 * It is asked at a completion and again inside a redemption's transaction,
 * under SSO's locks, so read the write connection every time, cache nothing and
 * keep nothing of one call for the next. SSO's tenant membership contract
 * requires the answer to stay true until the redeemer's transaction commits,
 * and offers no other protection, so take the application's membership guard of
 * the identity as the answer is read: a lock held until the asking transaction
 * ends, by a locking read on the write connection (a shared lock on the
 * identity's membership rows, say, or a lock on a guard row of the identity's
 * memberships). Every writer that revokes, expires or narrows a membership
 * takes the same guard before it writes, and before it ends the person's
 * sessions, so it waits for a redemption that read the membership to commit,
 * and its clean-up then finds the session that redemption wrote. SSO asks only
 * once its own locks are held (the application's guards come after the
 * package's in its lock order), and such a writer takes none of SSO's locks, so
 * the guard inverts no order. A change that creates or accepts a membership
 * calls SSO's scope widening first in its transaction (IAM-7.3), which takes
 * the identity's guard, the first of SSO's locks, before its own guard and the
 * write. A provisioner writing a new identity's membership guards only that
 * identity's own rows (`Provisioner`).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Memberships
{
    /**
     * Every one of the identity's current memberships, with when the person
     * accepted each, or those that could be read, marked incomplete; it throws
     * when it cannot read them.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Iam\Tenancy\MembershipSet
     *
     * @throws \Throwable
     */
    public function of(Identity $identity): MembershipSet;
}
