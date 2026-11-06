<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation;
use SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding as AuthenticationBinding;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * `laravel-authentication`'s passkey factor gate, calling MFA's passkey change
 * gate inside the passkey transaction (IAM-3.10).
 *
 * `registering()` hands the new credential, what its registration observed and
 * the enrolment binding its options were asked for to
 * `PasskeyChangeGate::registering()`, which associates it as a factor when the
 * application enables passkeys and the identity is a person, and answers the
 * association with MFA's factor id as its reference and MFA's whole result as
 * its completion: the factor's summary, the recovery codes made with the
 * identity's first factor (to reveal only once the registration has committed),
 * the pending session's verification, and on an active session the bound
 * session transition's answer (`completion()`), which is
 * `laravel-authentication`'s `factorChanged()` result (IAM-3.8). That reaches
 * the registration's caller as `PasskeyRegistration::$factor->completion`.
 * `removing()` hands the credential to `PasskeyChangeGate::removing()`, which
 * removes the factor it is associated as, with every check of a removal, and
 * ends the identity's other sessions through the bound session revoker; its
 * answer, `laravel-authentication`'s `factorRemoved()` result, reaches the
 * caller as `PasskeyRemoval::$completion`.
 *
 * Both run in `laravel-authentication`'s transaction on the shared storage
 * connection, before the passkey's row is written or deleted, so MFA's identity
 * state and factor locks come first and the session's row after them, and a
 * passkey is never removed leaving its factor standing, nor a factor made for a
 * passkey that is not stored. MFA refuses by throwing, so the whole change
 * rolls back. MFA is handed the caller as the values `laravel-authentication`
 * hands the gate: the identity, on the application it names, as an active
 * caller (`CallerContext::forIdentity()`), whose sign-in MFA reads from the
 * proof store and checks the registration's binding against, so it acts only on
 * that caller's own sign-in. Nothing is read from a request.
 * `laravel-authentication` hands the gate no pending credential and no client,
 * so MFA's events about the change name no client, and a registration made on a
 * pending sign-in (a bootstrap enrolment) is handed to MFA as the identity's
 * active caller, never as the pending session's (`CallerContext::forPending()`
 * needs the pending context, which only the credential resolves): MFA finds no
 * active sign-in of the caller's that the registration's binding names, and
 * refuses it as `not_found`, so the whole registration rolls back. Passkey
 * bootstrap enrolment on a pending sign-in is therefore refused until
 * `laravel-authentication` hands the gate the pending credential and the client
 * its `register()` and `remove()` already take (a member gap); it is never
 * served by reading them from a request.
 *
 * A registration whose options were asked for without a binding was not asked
 * for by a factor enrolment, so it stays a sign-in passkey and MFA is not
 * asked; one bound for anything but enrolment is refused (`not_found`), as MFA
 * associates a passkey only from the enrolment it was registered for. An
 * identity MFA cannot hold factors for holds no passkey factor: nothing is
 * associated or removed for it. A binding's session that is neither a non-empty
 * string nor an integer cannot be resolved and throws
 * `UnresolvedReferenceException` (IAM-8.2).
 *
 * It is mandatory, and bound while MFA's capability switch is on whether or not
 * an MFA application offers the `passkey` factor type now: left on
 * `laravel-authentication`'s default, removing a passkey enrolled as a factor
 * before the type was withdrawn would leave its factor standing. It holds
 * nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasskeyFactorGateAdapter implements PasskeyFactorGate
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate  $gate
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     */
    public function __construct(

        /** MFA's passkey change gate. */
        private PasskeyChangeGate $gate,

        /** Translates the registration's observed properties. */
        private ProofTranslator $proofs,
    ) {}

    /**
     * Associate the passkey being registered as an MFA factor, in the same
     * change, and answer the association.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey  $passkey
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  ?string  $name
     * @return ?\SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function registering(Identity $identity, string $application, RegisteredPasskey $passkey, ?AuthenticationBinding $binding, ?string $name): ?PasskeyFactorAssociation
    {
        if ($binding === null || !$identity instanceof MultiFactorAuthenticatable) {
            return null;
        }

        $result = $this->gate->registering(CallerContext::forIdentity($identity, $application), $this->registration($passkey, $binding), $name);

        return $result === null ? null : new PasskeyFactorAssociation($result->factor->id, $result);
    }

    /**
     * Remove the MFA factor of the passkey being removed, in the same change,
     * and answer MFA's completion.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  string  $passkeyId
     * @param  string  $credentialId
     * @return ?object
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function removing(Identity $identity, string $application, string $passkeyId, #[\SensitiveParameter] string $credentialId): ?object
    {
        if (!$identity instanceof MultiFactorAuthenticatable) {
            return null;
        }

        return $this->gate->removing(CallerContext::forIdentity($identity, $application), $credentialId);
    }

    /**
     * MFA's registration of the passkey: its credential, what its registration
     * observed and the enrolment it was bound to, refused when the binding is
     * for anything else.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey  $passkey
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function registration(RegisteredPasskey $passkey, AuthenticationBinding $binding): PasskeyRegistration
    {
        if ($binding->purpose !== AuthenticationPurpose::ENROLLMENT) {
            throw self::notForEnrolment();
        }

        $owner = IdentityReference::of($binding->identity);

        return new PasskeyRegistration(
            $passkey->credentialId,
            $this->proofs->properties($passkey->observed),
            new ProofBinding($owner->type, $owner->key, $binding->application, self::signIn($binding), Purpose::ENROLLMENT),
        );
    }

    /**
     * The sign-in MFA names the binding's session by: its key, as a string.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function signIn(AuthenticationBinding $binding): string
    {
        $session = $binding->sessionId;

        if ((!is_string($session) && !is_int($session)) || $session === '') {
            throw UnresolvedReferenceException::forSession($binding->application);
        }

        return (string) $session;
    }

    /**
     * The refusal of a registration bound for anything but enrolment.
     *
     * @return \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function notForEnrolment(): OperationRefusedException
    {
        return new OperationRefusedException(FailureReason::NOT_FOUND, 'A passkey is associated as a factor only from a registration bound for enrolment.');
    }
}
