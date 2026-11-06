<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Http\Request;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;

/**
 * MFA's application, named after `laravel-authentication`'s caller (IAM-3.12):
 * the guard that serves the request, the default guard as `Auth::shouldUse()`
 * leaves it, which a route's `auth` middleware sets to the guard that
 * authenticated the request. It is the MFA application of the same name, and
 * the guard whose validated session every MFA adapter of this package resolves
 * (`CurrentSession`), so the application MFA configures a request under is
 * never another guard than the one its sign-in, proofs and tenant are read
 * from.
 *
 * MFA asks it only at its edges, where it reads a caller from a request
 * (`CallerContext::fromRequest()`) or names the application a sign-in or
 * sign-out is recorded for: a guest's request, a console command's and a queued
 * job's included. Where MFA is given no guard (`fromRequest()` without one, as
 * MFA's own middleware and route binding call it), it answers the same guard as
 * MFA itself would without a resolver. Where MFA is given one, it does not:
 * MFA's contract hands it the request alone, never the guard, so a caller read
 * through another guard than the default (`CallerContext::fromRequest($request,
 * 'admin')`) is still named after the default guard, while its identity is the
 * one that other guard serves, and its freshness, step-up, challenges and
 * factor changes then act on the default guard's application; a `Login` or
 * `Logout` on another guard is named after the default guard too. An
 * application that reads a caller through a route's own guard calls
 * `Auth::shouldUse()` with that guard first, as the route's `auth` middleware
 * does, until MFA hands the resolver the guard (a member gap). MFA's contract
 * hands it the request, and it reads nothing of it (no path, host, header, query or body
 * names the application); it reads the guard's name, not its caller:
 * `Auth::caller()` is kept for the rest of the request once asked, so asking it
 * from inside MFA, before a sign-in completes, would leave the application a
 * stale caller. A default guard that names nothing names no application, and is
 * refused by throwing (IAM-8.2), never answered blank.
 *
 * It holds nothing between calls: the guard is read on every call (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApplicationResolverAdapter implements ApplicationResolver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     */
    public function __construct(

        /** Resolves the guard that serves the request. */
        private CurrentSession $sessions,
    ) {}

    /**
     * The application the request is for: the name of the guard that serves it.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function resolve(Request $request): string
    {
        $guard = $this->sessions->defaultGuard();

        if (trim($guard) === '') {
            throw UnresolvedReferenceException::forGuard($guard);
        }

        return $guard;
    }
}
