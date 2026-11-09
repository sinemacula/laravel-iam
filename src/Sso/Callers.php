<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Sso\Identities\Caller as SsoCaller;

/**
 * Names the caller of the application's own call into SSO as SSO takes it
 * (IAM-4.6, IAM-4.10, SSO-2.12): `laravel-authentication`'s `Caller`, read
 * where the application reads the request (`Auth::caller()`), as SSO's
 * `Identities\Caller`, the identity and the session SSO hands its freshness and
 * link confirmation contracts.
 *
 * SSO's management helpers, its link removal and a `link` flow's start each
 * take that caller, and this package's adapters judge the caller they are
 * handed and nothing else, so the application hands SSO the caller this names
 * (`of()`); a `link` redemption names its own (`LinkRedemption`). The identity
 * is named as SSO names an identity, its morph class and its key
 * (`IdentityReferences::reference()`), after the caller's guard is resolved as
 * one that holds sessions: either throws `UnresolvedReferenceException`
 * otherwise (IAM-8.2). The session is the one the caller's access credential
 * holds, by its key, while it is a session of the caller's guard that the
 * caller's identity owns; a caller with no session, a refresh or pending
 * credential, or a session of another guard or identity is named with none, so
 * SSO's freshness is `stale` for it, and its link confirmation `dependent`.
 *
 * A caller named while a transaction is open on the storage connection is named
 * with no session too: the freshness adapter reads the session plainly, and a
 * plain read inside a transaction opened before the call may answer from a
 * snapshot older than it (MySQL's `REPEATABLE READ`), still counting a proof
 * voided, or a session revoked, before then. So name the caller with no
 * transaction open, as SSO's own transaction is opened after the call.
 *
 * It keeps nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class Callers
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     */
    public function __construct(

        /** Names the caller as SSO names an identity. */
        private IdentityReferences $identities,

        /** Resolves the application to the guard it is, and tells whether a transaction is open. */
        private CurrentSession $sessions,
    ) {}

    /**
     * The caller as SSO takes it: its identity, and the session its access
     * credential holds while it is the caller's own and no transaction is open.
     *
     * @param  \SineMacula\Laravel\Authentication\Callers\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function of(Caller $caller): SsoCaller
    {
        $this->sessions->guard($caller->guard);

        $identity = $this->identities->reference($caller->identity);
        $session  = self::sessionOf($caller);

        return $session === null || $this->sessions->isInTransaction()
            ? new SsoCaller($identity)
            : new SsoCaller($identity, SignIn::reference($session, $caller->guard));
    }

    /**
     * The session the caller's access credential holds, when it is an Eloquent
     * session of the caller's guard that the caller's identity owns, or `null`
     * otherwise.
     *
     * @param  \SineMacula\Laravel\Authentication\Callers\Caller  $caller
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function sessionOf(Caller $caller): (EloquentSession&Model)|null
    {
        $session = $caller->session;

        if ($caller->credential !== CallerCredential::ACCESS || !$session instanceof EloquentSession || !$session instanceof Model) {
            return null;
        }

        return $caller->owns($session) ? $session : null;
    }
}
