<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Contracts\Auth\Guard;
use SineMacula\Laravel\AuditLog\Contracts\HeldActorReader;
use SineMacula\Laravel\AuditLog\Records\HeldActor;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * Gives audit-log the caller a `laravel-authentication` guard holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthenticationActorReader implements HeldActorReader
{
    /**
     * The caller the guard has bound; `null` for another guard or none bound.
     *
     * @param  string  $guard
     * @param  \Illuminate\Contracts\Auth\Guard  $instance
     * @return ?\SineMacula\Laravel\AuditLog\Records\HeldActor
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function read(string $guard, Guard $instance): ?HeldActor
    {
        if (!$instance instanceof AbstractGuard || !$instance->hasUser()) {
            return null;
        }

        try {
            $tenant = $instance->tenant();
        } catch (TenantUnavailableException) {
            $tenant = null;
        }

        $caller = new EventContext($guard, new ClientContext(null, null), $instance->identity(), $instance->principal(), $tenant, $instance->session());
        $actor  = References::of($caller->identityType, $caller->identityId);

        if ($actor === null) {
            return null;
        }

        return new HeldActor($actor, References::of($caller->principalType, $caller->principalId), References::tenant($caller->tenantId), $caller->sessionId);
    }
}
