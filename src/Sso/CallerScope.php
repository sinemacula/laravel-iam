<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;

/**
 * Hands SSO's freshness contract the caller of the application's own call into
 * SSO, as a plain value (IAM-4.6, SSO-2.12).
 *
 * SSO asks its freshness contract from its management helpers (a connection's
 * trust, a domain's claim, a key's rotation, the enforcement rule's update, a
 * link's removal) and from a `link` flow's start, and hands it neither the
 * caller nor the application. This package never takes either from the request
 * or the default guard, so outside a `link` redemption it runs
 * (`LinkRedemption`, handed its caller) SSO's freshness is `stale` unless the
 * application hands the caller in around its call: the identity it has
 * authenticated, read where it reads the request, and the application (the
 * `jwt` guard) whose current session is to be judged.
 *
 * `run()` resolves the application to its guard and names the caller as SSO
 * names an identity before it runs anything (either throws
 * `UnresolvedReferenceException` otherwise, IAM-8.2), opens this request's
 * record of callers (`LinkCallers`) with them, runs the work, and closes the
 * record however the work ends, answering what it returns. While it runs, SSO's
 * freshness judges the caller's own current session on that guard, and a guard
 * that serves another identity, or none, is `stale`. A caller handed in while a
 * transaction is already open on the storage connection is `stale` until that
 * transaction ends: its snapshot may be older than the call, and the session's
 * row cannot be locked where SSO asks. Nothing is kept once the work ends
 * (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class CallerScope
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     */
    public function __construct(

        /** Resolves the record of callers on each call. */
        private Container $container,

        /** Names the caller as SSO names an identity. */
        private IdentityReferences $identities,

        /** Resolves the application to the guard it is, and tells whether a transaction is open. */
        private CurrentSession $sessions,
    ) {}

    /**
     * Run the work with the caller handed in, on the application, for SSO's
     * freshness contract to judge, and answer what the work returns.
     *
     * @template T
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $caller
     * @param  \Closure(): T  $work
     * @return T
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function run(string $application, Identity $caller, \Closure $work): mixed
    {
        $this->sessions->guard($application);

        $reference = $this->identities->reference($caller);
        $callers   = $this->container->make(LinkCallers::class);

        $callers->open($application, $reference, $this->sessions->isInTransaction());

        try {
            return $work();
        } finally {
            $callers->close();
        }
    }
}
