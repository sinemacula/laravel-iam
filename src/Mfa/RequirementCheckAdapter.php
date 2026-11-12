<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck as AuthenticationRequirementCheck;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProviderTrust;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;

/**
 * `laravel-authentication`'s requirement check, answered by MFA's on the
 * subject's proofs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequirementCheckAdapter implements AuthenticationRequirementCheck
{
    /** @var list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind> The proofs read beside the first factor; an external reauthentication counts only through authentication's evidence policy. */
    private const array FURTHER_KINDS = [
        ProofKind::FIRST_FACTOR_REAUTHENTICATION,
        ProofKind::ADDITIONAL_FACTOR,
        ProofKind::RECOVERY_CODE,
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\RequirementCheck  $check
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator  $requirements
     */
    public function __construct(

        /** MFA's requirement check, the one asked. */
        private RequirementCheck $check,

        /** Translates the subject's proofs into MFA's. */
        private ProofTranslator $proofs,

        /** Translates the requirement into MFA's, and MFA's evaluation back. */
        private RequirementTranslator $requirements,
    ) {}

    /**
     * The parts of the requirement the subject's proofs leave unmet.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\RequirementSubject  $subject
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function evaluate(RequirementSubject $subject, Requirement $requirement): RequirementEvaluation
    {
        $identity = $subject->identity;

        if (!$identity instanceof MultiFactorAuthenticatable) {
            throw UnresolvedReferenceException::forMfaIdentity($identity::class);
        }

        $translated = $this->requirements->toMfa($requirement);
        $reference  = $subject->session === null ? SignIn::UNNAMED : SignIn::reference($subject->session, $subject->application);
        $signIn     = new SignIn(ProofOwner::of($identity), $subject->application, $reference, VerificationGeneration::current($identity));

        $further = array_reverse($subject->proofs(self::since($translated, $subject->now), self::FURTHER_KINDS, RequirementSubject::MAX_LIMIT));
        $proofs  = array_map(fn (RecordedProof $proof): Proof => $this->proofs->toMfa($proof, $signIn, ProviderTrust::withheld()), [$subject->firstFactor, ...$further]);

        return $this->requirements->evaluation($this->check->check($translated, ...$proofs));
    }

    /**
     * The oldest time a proof can meet a part, or `null` if one has no age.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\Carbon\CarbonImmutable
     */
    public static function since(MfaRequirement $requirement, CarbonImmutable $now): ?CarbonImmutable
    {
        $longest = 0;

        foreach ($requirement->parts() as $part) {

            $maxAge = $requirement->maxAge($part);

            if ($maxAge === null) {
                return null;
            }

            $longest = max($longest, $maxAge);
        }

        return $now->subSeconds($longest);
    }
}
