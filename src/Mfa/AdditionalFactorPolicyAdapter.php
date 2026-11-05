<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

/**
 * `laravel-authentication`'s additional-factor policy, answered by MFA's
 * requirement policy alone, which already composes the application's setting,
 * the identity's requirement and any re-enrolment obligation (IAM-3.1).
 *
 * MFA's policy is asked about the identity, on the application the sign-in is
 * for (the guard's name), with the first factor the identity signed in with as
 * MFA's proof, and its answer is handed back as `laravel-authentication`'s
 * requirement, part for part and age for age (IAM-3.14). Nothing is added to
 * the answer and nothing taken from it: whether the first factor meets it on
 * its own is MFA's to say.
 *
 * `laravel-authentication` names no session when it asks (at sign-in there is
 * none yet), so the first factor is bound to the sign-in no session key can
 * name (`SignIn::UNNAMED`), as its requirement check binds a sign-in's proofs,
 * and stamped with the identity's current verification generation, as MFA
 * stamps a proof it records. An identity MFA cannot hold factors for, or one
 * whose key names nothing, is refused by throwing (IAM-8.2), as is an answer
 * `laravel-authentication` cannot hold: no requirement is guessed.
 *
 * It reads nothing of its own but the generation, writes nothing and takes no
 * lock: it is asked inside `laravel-authentication`'s transaction, after the
 * session row's lock when there is one, so a lock taken here would invert the
 * order identity state, factors, session row.
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
     * The further factor the sign-in or session must prove, as MFA's
     * requirement policy asks for it.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function requirementFor(AdditionalFactorContext $context): Requirement
    {
        $identity = $context->identity;

        if (!$identity instanceof MultiFactorAuthenticatable) {
            throw UnresolvedReferenceException::forMfaIdentity($identity::class);
        }

        $signIn      = new SignIn(IdentityReference::of($identity), $context->application, SignIn::UNNAMED, VerificationGeneration::current($identity));
        $firstFactor = $this->proofs->toMfa($context->firstFactor, $signIn);

        return $this->requirements->toAuthentication($this->policy->requirementFor($identity, $context->application, $firstFactor));
    }
}
