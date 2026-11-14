<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProviderTrust;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFactorChangeGate;

/**
 * MFA's reauthenticator: the current session's newest reauthentication within
 * MFA's five minutes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReauthenticatorAdapter implements Reauthenticator
{
    /** @var list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind> The proofs that prove the first factor again. */
    private const array REAUTHENTICATIONS = [ProofKind::FIRST_FACTOR_REAUTHENTICATION, ProofKind::EXTERNAL_REAUTHENTICATION];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $current
     * @param  \SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy  $freshness
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     */
    public function __construct(

        /** Resolves the guard's current session for the identity. */
        private CurrentSession $current,

        /** Finds the session's newest reauthentication. */
        private FreshnessPolicy $freshness,

        /** Translates the proof into MFA's. */
        private ProofTranslator $proofs,
    ) {}

    /**
     * The identity's newest reauthentication on the application, if any.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function reauthenticate(MultiFactorAuthenticatable $identity, string $application): ?Proof
    {
        $session = $this->current->current($identity, $application);
        $current = StorageConnection::isInTransaction();

        $live  = Auth::sessions($application)->firstFactor($session) !== null;
        $proof = $live ? $this->freshness->freshProof($session, Operations::FIRST_ADDITIONAL_FACTOR, self::reauthentication(), current: $current) : null;

        if ($proof === null) {
            return null;
        }

        $signIn = new SignIn(ProofOwner::of($identity), $application, SignIn::reference($session, $application), VerificationGeneration::current($identity));

        return $this->proofs->toMfa($proof, $signIn, ProviderTrust::accepted($session->getTenantId()));
    }

    /**
     * A first-factor or provider reauthentication within MFA's maximum age.
     *
     * @return \SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement
     *
     * @throws \InvalidArgumentException
     */
    private static function reauthentication(): FreshnessRequirement
    {
        return new FreshnessRequirement(ConfiguredFactorChangeGate::REAUTHENTICATION_MAX_AGE, self::REAUTHENTICATIONS);
    }
}
