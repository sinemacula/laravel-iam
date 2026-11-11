<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Contracts;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The application's provisioner (IAM-7.1): what a person who signs in through
 * an SSO connection for the first time is made into, just in time.
 *
 * Both methods run inside the provisioning listener's one transaction on the
 * storage connection, in this order: `createIdentity()`, SSO's scope widening,
 * `createMembership()`, then SSO's link. Anything either throws, or a refused
 * link, rolls all of it back. Write every row on the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
interface Provisioner
{
    /**
     * Create a new identity for the result, and answer it.
     *
     * Always insert a new Eloquent model and answer that instance: never one
     * found by the result's email address or any other mapped attribute, which
     * would let whoever controls the connection take over an existing account.
     * The listener refuses an identity whose `wasRecentlyCreated` is false.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \Throwable
     */
    public function createIdentity(#[\SensitiveParameter] VerifiedResult $result): Identity;

    /**
     * Create the new identity's membership of the connection's tenant.
     *
     * It runs after SSO's scope widening holds the new identity's guard and
     * before the link, so take no lock on rows other writers share.
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
