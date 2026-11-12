<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Contracts;

use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * Brings a person's group grants into line with their provider groups at a
 * later sign-in.
 *
 * Runs after the redemption commits, in its own retried transaction on the
 * storage connection and outside SSO's locks. Throwing rolls it back and
 * refuses the sign-in. With none bound, nothing is re-synced.
 *
 * A widening grant takes SSO's identity guard first, so lock no shared rows
 * before writing through laravel-authorization's services.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
interface GroupResync
{
    /**
     * Bring the identity's group grants into line with the groups now reported.
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
