<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Http\Request;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver;

/**
 * MFA's application, named after `laravel-authentication`'s guard (IAM-3.12):
 * the guard MFA reads the caller through, or names the sign-in or sign-out
 * after, and otherwise the guard that serves the request, the default guard as
 * `Auth::shouldUse()` leaves it, which a route's `auth` middleware sets to the
 * guard that authenticated the request. It is the MFA application of the same
 * name, and the guard whose validated session every MFA adapter of this package
 * resolves (`CurrentSession`), so the application MFA configures a caller under
 * is never another guard than the one its identity, sign-in, proofs and tenant
 * are read from.
 *
 * MFA asks it only at its edges, where it reads a caller from a request
 * (`CallerContext::fromRequest()`) or names the application a sign-in or
 * sign-out is recorded for: a guest's request, a console command's and a queued
 * job's included. MFA hands it the guard wherever it knows one
 * (`resolveForGuard()`): the guard `fromRequest()` is given, the default guard
 * where it is given none (as MFA's own middleware and route binding call it),
 * and the guard of a `Login` or `Logout`. So a caller read through another
 * guard than the default (`CallerContext::fromRequest($request, 'admin')`) is
 * named after that guard, as MFA names it without a resolver, and its
 * freshness, step-up, challenges and factor changes act on that guard's
 * application, where its sessions are. `resolve()`, the form without a guard,
 * names the default guard through the same method.
 *
 * MFA's contract hands it the request, and it reads nothing of it (no path,
 * host, header, query or body names the application), nor whether the guard is
 * one of `laravel-authentication`'s `jwt` guards: a sign-in on a guard that
 * holds no sessions (an administrator's panel's session guard, say) is named
 * after that guard, and only the adapters that resolve a session on it refuse
 * it. It reads the guard's name, not its caller: `Auth::caller()` is kept for
 * the rest of the request once asked, so asking it from inside MFA, before a
 * sign-in completes, would leave the application a stale caller. A guard that
 * names nothing names no application, and is refused by throwing (IAM-8.2),
 * never answered blank.
 *
 * A pending sign-in's caller is the one exception MFA leaves it: MFA's pending
 * session resolver is handed the request alone, so a pending caller is read on
 * the default guard whatever guard `fromRequest()` is given (a member gap).
 *
 * It holds nothing between calls: the default guard is read on every call
 * (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApplicationResolverAdapter implements GuardApplicationResolver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     */
    public function __construct(

        /** Reads the default guard, the one that serves the request. */
        private CurrentSession $sessions,
    ) {}

    /**
     * The application the request is for: the name of the default guard, the
     * one that serves it.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function resolve(Request $request): string
    {
        return $this->resolveForGuard($request, $this->sessions->defaultGuard());
    }

    /**
     * The application the request is for through the guard: the guard's name.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function resolveForGuard(Request $request, string $guard): string
    {
        if (trim($guard) === '') {
            throw UnresolvedReferenceException::forGuard($guard);
        }

        return $guard;
    }
}
