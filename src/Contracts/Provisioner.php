<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Contracts;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Creates the identity and membership for a person's first SSO sign-in.
 *
 * Both methods run in one transaction on the storage connection; anything
 * thrown, or a refused link, rolls it all back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
interface Provisioner
{
    /**
     * Insert and answer a new identity for the result.
     *
     * Never answer one found by email or another mapped attribute: the listener
     * refuses an identity whose `wasRecentlyCreated` is false.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \Throwable
     */
    public function createIdentity(#[\SensitiveParameter] VerifiedResult $result): Identity;

    /**
     * Create the identity's membership of the tenant, taking no shared-row
     * lock.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return void
     *
     * @throws \Throwable
     */
    public function createMembership(Identity $identity, string $tenantId, #[\SensitiveParameter] VerifiedResult $result): void;
}
