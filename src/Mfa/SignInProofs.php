<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProviderTrust;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

/**
 * A session's recorded proofs as MFA's proofs of the sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignInProofs
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     */
    public function __construct(

        /** Translates the session's proofs to MFA's. */
        private ProofTranslator $proofs,
    ) {}

    /**
     * The proofs, oldest first, leaving out any MFA cannot express.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>  $recorded
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     * @throws \Throwable
     */
    public function of(MultiFactorAuthenticatable $identity, string $application, Session $session, array $recorded): array
    {
        $signIn = new SignIn(ProofOwner::of($identity), $application, SignIn::reference($session, $application), VerificationGeneration::current($identity));
        $trust  = ProviderTrust::accepted($session->getTenantId());
        $proofs = [];

        foreach ($recorded as $proof) {
            try {
                $proofs[] = $this->proofs->toMfa($proof, $signIn, $trust);
            } catch (\InvalidArgumentException) {
                continue;
            }
        }

        return $proofs;
    }

    /**
     * A session's proofs, oldest first, at most `MAX_LIMIT` of each kind.
     *
     * @param  \Closure(?list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>, int): list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>  $read
     * @return list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     */
    public static function history(\Closure $read): array
    {
        $recorded = $read(null, RequirementSubject::MAX_LIMIT);

        // A full read may have crowded out older proofs of another kind.
        if (count($recorded) === RequirementSubject::MAX_LIMIT) {
            $recorded = [];

            // Last kind first, so same-instant proofs read in kind order.
            foreach (array_reverse(ProofKind::cases()) as $kind) {
                $recorded = [...$recorded, ...$read([$kind], RequirementSubject::MAX_LIMIT)];
            }

            usort($recorded, static fn (RecordedProof $left, RecordedProof $right): int => $right->authenticatedAt <=> $left->authenticatedAt);
        }

        return array_reverse($recorded);
    }

    /**
     * Whether any of the proofs is a first factor.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>  $recorded
     * @return bool
     */
    public static function holdsAFirstFactor(array $recorded): bool
    {
        foreach ($recorded as $proof) {
            if ($proof->kind === ProofKind::FIRST_FACTOR) {
                return true;
            }
        }

        return false;
    }
}
