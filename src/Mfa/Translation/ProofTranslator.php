<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Proofs\Channel as AuthenticationChannel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\KeyProtection as AuthenticationKeyProtection;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind as AuthenticationProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation as AuthenticationEvaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties as AuthenticationProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding as AuthenticationBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Mfa\Assurance\Channel as MfaChannel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties as MfaProperties;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;
use SineMacula\Laravel\Mfa\Enums\KeyProtection as MfaKeyProtection;
use SineMacula\Laravel\Mfa\Enums\ProofKind as MfaProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Translates proofs between `laravel-authentication` and MFA (IAM-3.14,
 * IAM-5.2): a proof a session recorded becomes MFA's proof bound to the
 * sign-in, and a proof MFA verified becomes the proof result
 * `laravel-authentication` takes to satisfy a pending session or step one up,
 * accepted, and multifactor only when MFA says the proof itself supplies or
 * completes the multifactor evidence of the session's first factor.
 *
 * Both members spell the first four proof kinds, the four purposes, the key
 * protections and the channel kinds the same, and translate one to one.
 * `laravel-authentication`'s fifth kind, a reauthentication at the external
 * provider the session began with, is MFA's reauthentication with the first
 * factor, on an `external_provider` channel and with the reauthenticate purpose
 * it is recorded with; an SSO sign-in is a first factor in both. A recovery
 * code travels on no channel in MFA and on an unknown one in
 * `laravel-authentication`, which has no proof without one. The observed
 * properties cross under their own names (`backupEligible` is MFA's
 * `backupEligibility`, `phishingResistant` its `phishingResistance`).
 *
 * Nothing is relaxed on the way: a proof one member would refuse to build (an
 * additional factor without its factor, or on a password channel; a first
 * factor not made at sign-in; a credential backed up but not eligible for
 * backup) is refused here too, with the member's own exception, so no adapter
 * answers with a proof it guessed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofTranslator
{
    /** @var string The `amr` value only an evaluation reports, never a proof of its own. */
    private const string MULTIFACTOR_AMR = 'mfa';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ChannelTranslator  $channels
     */
    public function __construct(

        /** Translates the proofs' channels. */
        private ChannelTranslator $channels,
    ) {}

    /**
     * MFA's proof for one a session recorded, bound to the sign-in for the
     * purpose it was made for, stamped with the sign-in's verification
     * generation.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $proof
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\SignIn  $signIn
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \InvalidArgumentException
     */
    public function toMfa(RecordedProof $proof, SignIn $signIn): Proof
    {
        return new Proof(
            $this->kind($proof->kind),
            $proof->method,
            $this->channelOf($proof),
            $proof->factor,
            $this->properties($proof->observed),
            $proof->authenticatedAt,
            $signIn->binding($this->purpose($proof->purpose)),
            $signIn->generation,
        );
    }

    /**
     * The proof result `laravel-authentication` takes for a verification MFA
     * made: the proof's kind, method, channel, factor, observed properties and
     * time, its own `amr` values, a binding to the identity given (the one the
     * proof names), on the proof's application and sign-in, for its purpose,
     * and its own evaluation.
     *
     * `laravel-authentication` keeps the evaluation on the proof's row, and its
     * freshness reads "multifactor within so many seconds" as the newest proof
     * flagged multifactor, timed by that proof. So the proof is recorded
     * accepted (a result exists only for a proof MFA accepted after the
     * session's first factor), and multifactor exactly when the result's
     * `refreshesMultifactor` says the freshest evidence that the first factor
     * and this proof are multifactor is this proof's own: never from MFA's
     * evaluation of the whole session, which the result carries too and which
     * would flag a fresh email code multifactor because of an authenticator app
     * code proved hours before. A result without a proof is refused.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofResult
     *
     * @throws \InvalidArgumentException
     */
    public function toResult(VerificationResult $result, Identity $identity): ProofResult
    {
        $proof = $result->proof ?? throw self::unverified();

        $binding = new AuthenticationBinding($identity, $proof->binding->application, $proof->binding->sessionId, $this->toAuthenticationPurpose($proof->binding->purpose));

        return new ProofResult(
            AuthenticationProofKind::from($proof->kind->value),
            $proof->method,
            $proof->channel === null ? new AuthenticationChannel(AuthenticationChannelKind::UNKNOWN) : $this->channels->toAuthentication($proof->channel),
            $proof->reference,
            $this->toAuthenticationProperties($proof->properties),
            new AuthenticationEvaluation(true, $result->refreshesMultifactor),
            array_values(array_filter($result->amr, static fn (string $value): bool => $value !== self::MULTIFACTOR_AMR)),
            $proof->provedAt,
            $binding,
        );
    }

    /**
     * MFA's kind for `laravel-authentication`'s: the same kind, except that a
     * reauthentication at the external provider is a reauthentication with the
     * first factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @return \SineMacula\Laravel\Mfa\Enums\ProofKind
     */
    public function kind(AuthenticationProofKind $kind): MfaProofKind
    {
        return match ($kind) {
            AuthenticationProofKind::FIRST_FACTOR => MfaProofKind::FIRST_FACTOR,
            AuthenticationProofKind::FIRST_FACTOR_REAUTHENTICATION,
            AuthenticationProofKind::EXTERNAL_REAUTHENTICATION => MfaProofKind::FIRST_FACTOR_REAUTHENTICATION,
            AuthenticationProofKind::ADDITIONAL_FACTOR         => MfaProofKind::ADDITIONAL_FACTOR,
            AuthenticationProofKind::RECOVERY_CODE             => MfaProofKind::RECOVERY_CODE,
        };
    }

    /**
     * MFA's purpose for `laravel-authentication`'s, case by case.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Enums\Purpose
     */
    public function purpose(AuthenticationPurpose $purpose): MfaPurpose
    {
        return match ($purpose) {
            AuthenticationPurpose::SIGN_IN        => MfaPurpose::SIGN_IN,
            AuthenticationPurpose::REAUTHENTICATE => MfaPurpose::REAUTHENTICATE,
            AuthenticationPurpose::STEP_UP        => MfaPurpose::STEP_UP,
            AuthenticationPurpose::ENROLLMENT     => MfaPurpose::ENROLLMENT,
        };
    }

    /**
     * `laravel-authentication`'s purpose for MFA's, case by case.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose
     */
    public function toAuthenticationPurpose(MfaPurpose $purpose): AuthenticationPurpose
    {
        return match ($purpose) {
            MfaPurpose::SIGN_IN        => AuthenticationPurpose::SIGN_IN,
            MfaPurpose::REAUTHENTICATE => AuthenticationPurpose::REAUTHENTICATE,
            MfaPurpose::STEP_UP        => AuthenticationPurpose::STEP_UP,
            MfaPurpose::ENROLLMENT     => AuthenticationPurpose::ENROLLMENT,
        };
    }

    /**
     * MFA's observed properties for `laravel-authentication`'s, each kept as it
     * was observed, or not.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @return \SineMacula\Laravel\Mfa\Assurance\ObservedProperties
     *
     * @throws \InvalidArgumentException
     */
    public function properties(AuthenticationProperties $observed): MfaProperties
    {
        return new MfaProperties(
            $observed->userPresence,
            $observed->userVerification,
            $observed->backupEligible,
            $observed->backupState,
            $observed->phishingResistant,
            $observed->keyProtection === null ? null : MfaKeyProtection::from($observed->keyProtection->value),
        );
    }

    /**
     * `laravel-authentication`'s observed properties for MFA's, each kept as it
     * was observed, or not.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @return \SineMacula\Laravel\Authentication\Proofs\ObservedProperties
     */
    public function toAuthenticationProperties(MfaProperties $properties): AuthenticationProperties
    {
        return new AuthenticationProperties(
            $properties->userPresence,
            $properties->userVerification,
            $properties->backupEligibility,
            $properties->backupState,
            $properties->phishingResistance,
            $properties->keyProtection === null ? null : AuthenticationKeyProtection::from($properties->keyProtection->value),
        );
    }

    /**
     * The refusal of a verification result that holds no proof to hand over.
     *
     * @return \InvalidArgumentException
     */
    private static function unverified(): \InvalidArgumentException
    {
        return new \InvalidArgumentException('Only a verification that made a proof can be handed to laravel-authentication.');
    }

    /**
     * MFA's channel for a recorded proof: none for a recovery code, an
     * `external_provider` one for a reauthentication at the external provider
     * (with the provider's reference when it was recorded on one), and the
     * recorded channel otherwise.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $proof
     * @return ?\SineMacula\Laravel\Mfa\Assurance\Channel
     *
     * @throws \InvalidArgumentException
     */
    private function channelOf(RecordedProof $proof): ?MfaChannel
    {
        return match ($proof->kind) {
            AuthenticationProofKind::RECOVERY_CODE             => null,
            AuthenticationProofKind::EXTERNAL_REAUTHENTICATION => new MfaChannel(
                MfaChannelKind::EXTERNAL_PROVIDER,
                $proof->channel->kind === AuthenticationChannelKind::EXTERNAL_PROVIDER ? $proof->channel->reference : null,
            ),
            default => $this->channels->toMfa($proof->channel),
        };
    }
}
