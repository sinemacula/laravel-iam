<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProviderTrust;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

/**
 * `laravel-authentication`'s additional-factor policy, answered by MFA's
 * requirement policy alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AdditionalFactorPolicyAdapter implements AdditionalFactorPolicy
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\RequirementPolicy  $policy
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator  $requirements
     */
    public function __construct(

        /** MFA's requirement policy, the one asked. */
        private RequirementPolicy $policy,

        /** Translates the first factor into MFA's proof. */
        private ProofTranslator $proofs,

        /** Translates MFA's answer into `laravel-authentication`'s requirement. */
        private RequirementTranslator $requirements,
    ) {}

    /**
     * The further factor MFA's policy asks the sign-in or session for.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function requirementFor(AdditionalFactorContext $context): Requirement
    {
        $identity = $context->identity;

        if (!$identity instanceof MultiFactorAuthenticatable) {
            throw UnresolvedReferenceException::forMfaIdentity($identity::class);
        }

        $signIn      = new SignIn(ProofOwner::of($identity), $context->application, SignIn::UNNAMED, VerificationGeneration::current($identity));
        $firstFactor = $this->proofs->toMfa($context->firstFactor, $signIn, ProviderTrust::accepted($context->provenSession?->getTenantId()));

        return $this->requirements->toAuthentication($this->policy->requirementFor($identity, $context->application, $firstFactor));
    }
}
