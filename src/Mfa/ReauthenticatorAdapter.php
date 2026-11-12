<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
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
 * MFA's reauthenticator, answered with the newest first-factor reauthentication
 * proof `laravel-authentication`'s freshness policy finds on the identity's
 * current session (IAM-3.5).
 *
 * The application is the guard of the same name, and the session is that
 * guard's current one, held by the identity asked about. The person proves the
 * first factor again through `laravel-authentication`
 * (`Auth::sessions()->reauthenticate()`, or at the external provider the
 * session began with), which records the proof on the session; this adapter
 * only finds it. It asks the freshness policy for the session's newest proof
 * meeting `first_additional_factor`, the operation a reauthentication
 * authorises in `laravel-authentication`, held to a reauthentication with the
 * first factor or at the external provider made within the five minutes MFA
 * allows one to authorise a change, so the application's own setting for the
 * operation can only make it stricter. The proof is MFA's reauthentication with
 * the first factor, bound to the identity, the application and the session for
 * `reauthenticate`, under the identity's current verification generation; a
 * reauthentication at the provider names its connection as the proof store's
 * proofs do (`ProviderTrust::accepted()`, with the session's tenant).
 *
 * MFA asks it from its own factor-change gate, inside MFA's transaction, after
 * MFA's own locks, and grants the change on the answer: before the proof is
 * read, the session's row is locked through `Auth::sessions()->firstFactor()`,
 * after them, as every adapter takes it, a session that is no longer one of the
 * guard's live, active sessions of a person answers no reauthentication, and
 * the freshness policy is then asked current, under that lock, on the session's
 * proofs as committed, so a reauthentication recorded before the call counts
 * and one voided before it never does, whatever the transaction read first.
 * Outside a transaction on the session model's connection (MFA's contract kit,
 * or the application's own call) nothing acts on the answer atomically, so
 * those are plain reads, and the policy is asked plainly, as it refuses a
 * current judgement there (`CurrentSession::isInTransaction()`). A guard that
 * holds no session of the identity, or an application that is no guard of
 * `laravel-authentication`'s, cannot be resolved and throws (IAM-8.2), so the
 * change asking for it rolls back.
 *
 * It holds nothing between calls (IAM-8.1).
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
        $current = $this->current->isInTransaction();

        $live  = Auth::sessions($application)->firstFactor($session) !== null;
        $proof = $live ? $this->freshness->freshProof($session, Operations::FIRST_ADDITIONAL_FACTOR, self::reauthentication(), current: $current) : null;

        if ($proof === null) {
            return null;
        }

        $signIn = new SignIn(ProofOwner::of($identity), $application, SignIn::reference($session, $application), VerificationGeneration::current($identity));

        return $this->proofs->toMfa($proof, $signIn, ProviderTrust::accepted($session->getTenantId()));
    }

    /**
     * The reauthentication MFA takes to authorise a change: with the first
     * factor or at the external provider, within the last five minutes.
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
