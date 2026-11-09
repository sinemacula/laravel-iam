<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProviderTrust;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

/**
 * The proofs one of `laravel-authentication`'s sessions recorded, as MFA's
 * proofs of the sign-in the session is (IAM-3.11, IAM-3.12): what the proof
 * store answers for the guard's current session, and what the `mfa` context
 * contributor hands MFA for the session it is given, so the two read a
 * session's proofs alike.
 *
 * The session's proofs are read by the caller, through
 * `laravel-authentication`'s public readers (`Auth::sessions($guard)->proofs()`
 * and `firstFactor()`, or the contribution subject's own), and handed in oldest
 * first. Each is translated to MFA's proof bound to the sign-in (the identity,
 * the application, the session's key) and stamped with the identity's current
 * verification generation, read once for them all. An SSO sign-in's first
 * factor, or a reauthentication at the provider, names its connection only when
 * it carries evidence SSO's evidence contract accepted and the session's
 * tenant, if any, trusts the connection (`ProviderTrust::accepted()`). A proof
 * MFA cannot express (an additional factor that names no factor, say) is left
 * out rather than guessed at, and so is one that names a factor the identity no
 * longer holds in MFA's factor table, read on the write connection only when a
 * proof names a factor, so a factor MFA has just deleted, in its own
 * transaction or in one since committed, stops counting at once and a replica
 * that has not caught up cannot bring it back.
 *
 * It reads nothing of the request or the guard, and holds no state between
 * calls (IAM-8.1).
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
     * The session's recorded proofs, oldest first as handed in, as MFA's proofs
     * of the identity's sign-in on the application that still count.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>  $recorded
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    public function of(MultiFactorAuthenticatable $identity, string $application, Session $session, array $recorded): array
    {
        $signIn = new SignIn(IdentityReference::of($identity), $application, SignIn::reference($session, $application), VerificationGeneration::current($identity));
        $trust  = ProviderTrust::accepted($session->getTenantId());
        $proofs = [];

        foreach ($recorded as $proof) {
            try {
                $proofs[] = $this->proofs->toMfa($proof, $signIn, $trust);
            } catch (\InvalidArgumentException) {
                continue;
            }
        }

        return self::held($identity, $proofs);
    }

    /**
     * Whether the identity still holds the factor, read from MFA's factor table
     * on the write connection.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return bool
     */
    public static function holds(MultiFactorAuthenticatable $identity, string $factorId): bool
    {
        return in_array($factorId, self::factors($identity), true);
    }

    /**
     * The factor's id, as a proof made with it names it: its identifier as
     * text, so a factor identified by a number is the one a proof naming that
     * number names.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return string
     */
    public static function factorReference(Factor $factor): string
    {
        $id = $factor->getFactorIdentifier();

        return is_scalar($id) ? (string) $id : '';
    }

    /**
     * Whether any of the proofs is a first factor, as `laravel-authentication`
     * recorded it.
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

    /**
     * The proofs that still count: each that names no factor, and each that
     * names a factor the identity still holds.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    private static function held(MultiFactorAuthenticatable $identity, array $proofs): array
    {
        if (array_filter($proofs, static fn (Proof $proof): bool => $proof->reference !== null) === []) {
            return $proofs;
        }

        $factors = self::factors($identity);

        return array_values(array_filter($proofs, static fn (Proof $proof): bool => $proof->reference === null || in_array($proof->reference, $factors, true)));
    }

    /**
     * The identity's factors, as a proof made with each names it, read from
     * MFA's factor table on the write connection.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return array<int, string>
     */
    private static function factors(MultiFactorAuthenticatable $identity): array
    {
        return array_map(
            static fn (Factor $factor): string => self::factorReference($factor),
            $identity->authFactors()->useWritePdo()->get()->all(),
        );
    }
}
