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
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProviderTrust;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;

/**
 * `laravel-authentication`'s requirement check, answered by MFA's, so sign-in,
 * a tenant's policy, step-up and authorization conditions all get the same
 * answer (IAM-3.2).
 *
 * The requirement crosses as MFA's, part for part and age for age, and MFA's
 * check judges the subject's first factor with the further proofs the subject
 * reads; the parts it leaves unmet are the answer (IAM-3.14). The proofs are
 * read in one bounded query, as `laravel-authentication` asks: only the kinds a
 * requirement can be met with after the first factor, only those made since the
 * oldest time a part's maximum age allows (all of them when a part has none),
 * and at most as many as one query returns. A part met only by a proof older
 * than the newest that many is left unmet, never guessed met. A
 * reauthentication at the external provider is not read:
 * `laravel-authentication` counts no part of a requirement met by one, and on
 * its own it is all such a proof could meet.
 *
 * An external provider's first factor is handed to MFA naming no connection
 * (`ProviderTrust::withheld()`), so no combination policy can trust it by its
 * connection here: `laravel-authentication` asks its external evidence policy
 * first, with the tenant whose requirement it is, and that policy
 * (`ExternalEvidencePolicyAdapter::meets()`) counts only the evidence SSO
 * accepted, from a connection that tenant trusts. The check is told neither, so
 * trusting the connection here would count every sign-in through it, for every
 * tenant, whatever SSO accepted (IAM-4.6, IAM-5.1).
 *
 * Each proof is bound to the session judged (its key, as MFA names a sign-in),
 * or, at sign-in, before the session is written, to the sign-in no session key
 * can name (`SignIn::UNNAMED`); MFA counts only the proofs of one sign-in, so
 * every proof of one judgement is bound to the same. Each is stamped with the
 * identity's current verification generation, as MFA stamps a proof it records.
 * An identity MFA cannot hold factors for, or a session or identity whose key
 * names nothing, is refused by throwing (IAM-8.2), as is a proof MFA would not
 * build: no answer is guessed.
 *
 * It takes no lock: it is asked inside `laravel-authentication`'s transaction,
 * after the session row's lock when a session is judged, and reads the
 * generation and whatever MFA's check reads without locking, so the order
 * identity state, factors, session row is never inverted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequirementCheckAdapter implements AuthenticationRequirementCheck
{
    /** @var list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind> The kinds of proof read beside the first factor: those a requirement can be met with, but a reauthentication at an external provider, which `laravel-authentication` counts through its external evidence policy first (`laravel-authorization`'s requirement checker, with no such policy, reads that too: `Authorization\RequirementCheckerAdapter::FURTHER_KINDS`). */
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
     * The parts of the requirement the subject's proofs leave unmet, as MFA's
     * requirement check judges them.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\RequirementSubject  $subject
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
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
        $signIn     = new SignIn(IdentityReference::of($identity), $subject->application, $reference, VerificationGeneration::current($identity));

        $further = array_reverse($subject->proofs(self::since($translated, $subject->now), self::FURTHER_KINDS, RequirementSubject::MAX_LIMIT));
        $proofs  = array_map(fn (RecordedProof $proof): Proof => $this->proofs->toMfa($proof, $signIn, ProviderTrust::withheld()), [$subject->firstFactor, ...$further]);

        return $this->requirements->evaluation($this->check->check($translated, ...$proofs));
    }

    /**
     * The oldest time a proof can meet a part of the requirement at: its
     * longest maximum age before the time judged, or `null` when a part has
     * none, so any proof may meet it. `laravel-authorization`'s requirement
     * checker bounds its read the same way.
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
