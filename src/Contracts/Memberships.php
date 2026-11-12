<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Contracts;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Tenancy\MembershipSet;

/**
 * Answers which tenants an identity is a current member of, and when the person
 * accepted each.
 *
 * Asked inside SSO's redemption locks, so read the write connection, cache
 * nothing, and take the application's membership guard of the identity with a
 * locking read held until the transaction ends. Mark a partial read incomplete;
 * throw when the read fails.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Memberships
{
    /**
     * The identity's current memberships, marked incomplete if partly read.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Iam\Tenancy\MembershipSet
     *
     * @throws \Throwable
     */
    public function of(Identity $identity): MembershipSet;
}
