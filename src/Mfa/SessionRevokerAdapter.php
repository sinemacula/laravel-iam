<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\RemovalRevocation;

/**
 * MFA's session revoker, ending `laravel-authentication`'s sessions
 * synchronously inside MFA's transaction when a factor is removed or the
 * identity reset, and carrying the current session's new pending credential
 * back through MFA's removal result (IAM-3.7, mandatory).
 *
 * A removal is made from a sign-in, which MFA names with its application: the
 * session of that key on the guard of the same name, held by the identity, read
 * whatever the guard holds now (`CurrentSession::named()`), so a removal made
 * from a queued job, a console command or a request another guard serves judges
 * the sign-in MFA named. A sign-in that is no session of the identity's on that
 * guard, an application that is no guard of `laravel-authentication`'s that
 * holds sessions, or an identity `laravel-authentication` does not sign in is
 * refused by throwing (IAM-8.2), so the removal rolls back rather than sparing
 * a session nobody judged. A reset names no application and no sign-in, and is
 * often made by someone else, from an admin panel's session guard, a console
 * command or a queued job, so it goes through the default guard when that is a
 * `jwt` guard and otherwise through the first `jwt` guard declared
 * (`CurrentSession::identitySessions()`); it throws only when no `jwt` guard is
 * declared at all.
 *
 * `factorRemoved()` then ends every other session of the identity, pending ones
 * included, voids the current session's proofs made with the factor and judges
 * it again by `laravel-authentication`'s own rules: kept active, returned to
 * pending with a new pending credential, or revoked. The revocation says so
 * (`RemovalRevocation::judged()`), so MFA hands no shortfall to the session
 * transition as well, and carries `laravel-authentication`'s removal result,
 * the credential included, as MFA's completion. A reset calls `factorReset()`,
 * which ends every session of the identity on every guard, the current one
 * included, and forgets the binding of the guard it went through. Both run as
 * savepoints of MFA's transaction, after its locks, so they commit or roll back
 * with the change.
 *
 * Stateless: the guard and the session are read on every call (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionRevokerAdapter implements SessionRevoker
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     */
    public function __construct(

        /** Resolves the guard, its session service and the sign-in a removal is made from. */
        private CurrentSession $sessions,
    ) {}

    /**
     * End the identity's other sessions, void the current session's proofs made
     * with the factor and judge it again.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @param  string  $application
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\RemovalRevocation
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function factorRemoved(MultiFactorAuthenticatable $identity, string $factorId, string $application, string $session): RemovalRevocation
    {
        $owner   = $this->sessions->identity($identity);
        $current = $this->sessions->named($identity, $application, $session);

        return RemovalRevocation::judged($this->sessions->sessions($application)->factorRemoved($owner, $factorId, $current));
    }

    /**
     * End every session of the identity, the current one included, through the
     * default guard when it holds sessions and otherwise through the first
     * guard declared that does.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function revokeAll(MultiFactorAuthenticatable $identity): void
    {
        $owner = $this->sessions->identity($identity);

        $this->sessions->identitySessions()->factorReset($owner);
    }
}
