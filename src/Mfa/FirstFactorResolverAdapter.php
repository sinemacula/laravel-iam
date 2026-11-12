<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * MFA's first factor, read from the first-factor proof `laravel-authentication`
 * recorded on the current session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FirstFactorResolverAdapter implements FirstFactorResolver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter  $store
     */
    public function __construct(

        /** Reads the session's proofs. */
        private ProofStoreAdapter $store,
    ) {}

    /**
     * The first factor of the identity's current sign-in, if MFA can read it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function resolve(MultiFactorAuthenticatable $identity, string $application): ?Proof
    {
        return $this->store->firstFactor($identity, $application);
    }
}
