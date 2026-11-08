<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;

/**
 * Hands SSO's freshness contract the caller of the application's own call into
 * SSO, as a plain value (IAM-4.6, SSO-2.12).
 *
 * SSO asks its freshness contract from its management helpers (a connection's
 * trust, a domain's claim, a key's rotation, the enforcement rule's update, a
 * link's removal) and from a `link` flow's start, and hands it no caller. This
 * package never takes one from the request, the default guard or the session a
 * guard serves, so outside a `link` redemption it runs (`LinkRedemption`,
 * handed its caller) SSO's freshness is `stale` unless the application hands
 * the caller in around its call: `laravel-authentication`'s `Caller`, read
 * where the application reads the request (`Auth::caller()`), whose guard is
 * the application (the `jwt` guard) and whose session is the one judged.
 *
 * `run()` resolves the caller's guard and names its identity as SSO names an
 * identity before it runs anything (either throws
 * `UnresolvedReferenceException` otherwise, IAM-8.2), opens this request's
 * record of callers (`LinkCallers`) with the caller, runs the work, and closes
 * the record however the work ends, answering what it returns. While it runs,
 * SSO's freshness judges the session the caller's access credential holds, when
 * it is a session of the caller's guard that the caller's identity owns, and
 * nothing else: a caller with no session, a refresh or pending credential, or a
 * session of another guard or identity is `stale`. A caller handed in while a
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
     * Run the work with the caller handed in, for SSO's freshness contract to
     * judge, and answer what the work returns.
     *
     * @template T
     *
     * @param  \SineMacula\Laravel\Authentication\Callers\Caller  $caller
     * @param  \Closure(): T  $work
     * @return T
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function run(Caller $caller, \Closure $work): mixed
    {
        $this->sessions->guard($caller->guard);
        $this->identities->reference($caller->identity);

        $callers = $this->container->make(LinkCallers::class);

        $callers->open($caller, $this->sessions->isInTransaction());

        try {
            return $work();
        } finally {
            $callers->close();
        }
    }
}
