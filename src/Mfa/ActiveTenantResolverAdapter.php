<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * MFA's active tenant: the tenant of the session the application's guard
 * validated for the identity, or none before a session exists.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ActiveTenantResolverAdapter implements ActiveTenantResolver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     */
    public function __construct(

        /** Resolves the application's guard and the session it holds. */
        private CurrentSession $sessions,
    ) {}

    /**
     * The tenant of the identity's session on the application, if any.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function activeTenant(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        $guard = $this->sessions->guard($application);
        $asked = ProofOwner::of($identity);
        $owner = $guard->identity();

        if ($owner === null || !ProofOwner::of($owner)->is($asked)) {
            return null;
        }

        return $guard->session()?->getTenantId();
    }
}
