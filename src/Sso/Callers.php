<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Sso\Identities\Caller as SsoCaller;

/**
 * Names the caller of the application's own call into SSO as SSO's `Caller`,
 * with its own session only while no transaction is open.
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

        /** Resolves the application to the guard it is. */
        private CurrentSession $sessions,
    ) {}

    /**
     * The caller as SSO takes it.
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

        // A plain read in an older transaction may see a stale snapshot.
        return $session === null || StorageConnection::isInTransaction()
            ? new SsoCaller($identity)
            : new SsoCaller($identity, SignIn::reference($session, $caller->guard));
    }

    /**
     * The session the caller's access credential holds, if the caller owns it.
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
