<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Contracts\Auth\Factory;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * The `laravel-authentication` caller a guard already holds (IAM-9.7), read
 * without ever triggering authentication, for the caller's context contributor
 * and for the caller carried into a queued job.
 *
 * The guards are walked as audit-log walks them for its own actor: the guards
 * `audit-log.actor.guards` lists, in order, or the default guard. The first
 * that holds a user decides, and the walk stops there: when it is no package
 * guard (`AbstractGuard`) it is audit-log's to read, or a guard whose accessors
 * cannot be known to read only what is bound, and there is no caller, rather
 * than one read from a later guard, which could name another person.
 *
 * Each guard is asked `hasUser()`, which only says whether an identity is
 * bound, and only once one is, the identity, the principal, the session and the
 * active tenant, which a package guard then answers from what is bound
 * (`AbstractGuard::user()` returns the bound identity before it would resolve
 * anything), without resolving the request, loading anyone or dispatching
 * anything. Another `ContextualGuard` promises no such thing, so it is never
 * read. `Auth::caller()`, which reads the request and may prove (and so revoke)
 * a refresh token, is never called, nor the guard's authentication context,
 * which reads proofs and runs contributors, and no request is read. A guard
 * that is not configured is no caller, and a tenant that cannot be loaded is no
 * tenant, since audit-log loses a record whose contributor throws; a guard
 * configured with a driver that cannot be built lets `AuthManager`'s exception
 * through, as audit-log's own walk of the same guards does, a misconfiguration
 * `audit-log:check` reports.
 *
 * Everything is read when it is asked, from the guards and the configuration
 * current then, and nothing is kept (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class HeldCaller
{
    /** @var string The key of the guards audit-log reads the ambient actor from. */
    private const string ACTOR_GUARDS = 'audit-log.actor.guards';

    /** @var string The key of the application's guards. */
    private const string GUARDS = 'auth.guards';

    /** @var string The key naming the default guard. */
    private const string DEFAULT_GUARD = 'auth.defaults.guard';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Gives each guard by name. */
        private Factory $auth,

        /** Configuration the guards to walk are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The caller the first guard holding a user holds, when it is a package
     * guard; `null` when no guard holds one, a guard is not configured, or the
     * first holding one is no package guard.
     *
     * @return ?\SineMacula\Laravel\Iam\Audit\CallerSnapshot
     */
    public function current(): ?CallerSnapshot
    {
        foreach ($this->guardNames() as $name) {

            if (!is_array($this->config->get(self::GUARDS . '.' . $name))) {
                return null;
            }

            $guard = $this->auth->guard($name);

            if (!$guard->hasUser()) {
                continue;
            }

            return $guard instanceof AbstractGuard ? CallerSnapshot::of(self::contextOf($name, $guard)) : null;
        }

        return null;
    }

    /**
     * The guard's bound identity, principal, active tenant and session as
     * `laravel-authentication` snapshots them for its own events; the tenant is
     * left out when the guard cannot load it.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function contextOf(string $name, AbstractGuard $guard): EventContext
    {
        try {
            $tenant = $guard->tenant();
        } catch (TenantUnavailableException) {
            $tenant = null;
        }

        return new EventContext($name, new ClientContext(null, null), $guard->identity(), $guard->principal(), $tenant, $guard->session());
    }

    /**
     * The names of the guards to walk: the list `audit-log.actor.guards`
     * configures, or the default guard alone. A list member that is no name is
     * skipped, as is a default that is none.
     *
     * @return list<string>
     */
    private function guardNames(): array
    {
        $guards = $this->config->get(self::ACTOR_GUARDS);
        $names  = [];

        foreach (is_array($guards) && $guards !== [] ? $guards : [$this->config->get(self::DEFAULT_GUARD)] as $name) {

            if (!is_string($name) || $name === '') {
                continue;
            }

            $names[] = $name;
        }

        return $names;
    }
}
