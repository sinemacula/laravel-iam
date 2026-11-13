<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\RemovalRevocation;

/**
 * MFA's session revoker, ending `laravel-authentication`'s sessions inside
 * MFA's transaction.
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
     * @param  \SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation  $decisions
     */
    public function __construct(

        /** Resolves the guard, its session service and the sign-in a removal is made from. */
        private CurrentSession $sessions,

        /** Forgets the decisions that read the identity's authentication. */
        private DecisionCacheInvalidation $decisions,
    ) {}

    /**
     * End other sessions, void the factor's proofs, rejudge the current one.
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
        $removal = $this->sessions->sessions($application)->factorRemoved($owner, $factorId, $current);

        $this->decisions->authenticationChanged($identity, $session);

        return RemovalRevocation::judged($removal);
    }

    /**
     * End every session of the identity and forget the decisions they read.
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

        $this->decisions->authenticationChanged($identity);
    }
}
