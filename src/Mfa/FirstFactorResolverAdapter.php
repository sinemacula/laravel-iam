<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * MFA's first-factor resolver, answered with the first-factor proof
 * `laravel-authentication` recorded on the identity's current session
 * (IAM-3.11).
 *
 * The sign-in is the guard's current session when it is the identity's, as the
 * proof store names it, and its first factor is the oldest counting
 * first-factor proof `Auth::sessions($guard)->firstFactor()` reads, translated
 * to MFA's proof bound to the sign-in and stamped with the identity's current
 * verification generation. Nothing is answered for a guard holding no session
 * of the identity, for a session that is no longer live and active, or for a
 * first factor MFA cannot express, so MFA trusts no first factor it was not
 * given.
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

        /** Reads the session's proofs as the proof store does. */
        private ProofStoreAdapter $store,
    ) {}

    /**
     * The first factor the identity's current sign-in on the application was
     * made with, or `null` when it has none.
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
