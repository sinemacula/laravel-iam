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
 * MFA asks it whenever a request is bound, a guest's, a console command's and a
 * queued job's included, and answers the same guard for them as MFA itself
 * would without a resolver, so binding it never moves a change made outside a
 * signed-in request to another application. It reads the guard's name, not its
 * caller: `Auth::caller()` is kept for the rest of the request once asked, so
 * asking it from inside MFA, before a sign-in completes, would leave the
 * application a stale caller. A default guard that names nothing names no
 * application, and is refused by throwing (IAM-8.2), never answered blank.
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
