<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation;
use SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding as AuthenticationBinding;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\ClientContext as MfaClient;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * `laravel-authentication`'s passkey factor gate, calling MFA's passkey change
 * gate inside the passkey transaction.
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
     * @param  \SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter  $pendings
     */
    public function __construct(

        /** MFA's passkey change gate. */
        private PasskeyChangeGate $gate,

        /** Translates the registration's observed properties. */
        private ProofTranslator $proofs,

        /** Reads the pending session a registration's pending credential names. */
        private PendingSessionResolverAdapter $pendings,
    ) {}

    /**
     * Associate the passkey as a factor for the pending sign-in or caller.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey  $passkey
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  ?string  $name
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $pending
     * @return ?\SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function registering(
        Identity $identity,
        string $application,
        RegisteredPasskey $passkey,
        ?AuthenticationBinding $binding,
        ?string $name,
        ClientContext $client,
        #[\SensitiveParameter] ?Secret $pending,
    ): ?PasskeyFactorAssociation {
        if ($binding === null || !$identity instanceof MultiFactorAuthenticatable) {
            return null;
        }

        $registration = $this->registration($passkey, $binding);
        $caller       = $this->caller($identity, $application, ClientTranslator::toMfa($client), $pending);
        $result       = $this->gate->registering($caller, $registration, $name);

        return $result === null ? null : new PasskeyFactorAssociation($result->factor->id, $result);
    }

    /**
     * Remove the passkey's MFA factor and answer MFA's completion.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  string  $passkeyId
     * @param  string  $credentialId
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ?object
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function removing(Identity $identity, string $application, string $passkeyId, #[\SensitiveParameter] string $credentialId, ClientContext $client): ?object
    {
        if (!$identity instanceof MultiFactorAuthenticatable) {
            return null;
        }

        return $this->gate->removing(CallerContext::forIdentity($identity, $application, ClientTranslator::toMfa($client)), $credentialId);
    }

    /**
     * MFA's caller: the credential's pending session, else the identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $pending
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function caller(MultiFactorAuthenticatable $identity, string $application, MfaClient $client, #[\SensitiveParameter] ?Secret $pending): CallerContext
    {
        if ($pending === null) {
            return CallerContext::forIdentity($identity, $application, $client);
        }

        $context = $this->pendings->fromCredential($application, $pending->reveal());

        if ($context === null || !ProofOwner::of($context->identity)->is(ProofOwner::of($identity))) {
            throw new OperationRefusedException(FailureReason::NOT_FOUND, 'The pending credential names no pending sign-in of the identity on the application.');
        }

        return CallerContext::forPending($context, $client);
    }

    /**
     * MFA's registration of the passkey, refused unless for an enrolment.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey  $passkey
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function registration(RegisteredPasskey $passkey, AuthenticationBinding $binding): PasskeyRegistration
    {
        if ($binding->purpose !== AuthenticationPurpose::ENROLLMENT) {
            throw self::notForEnrolment();
        }

        $owner = ProofOwner::of($binding->identity);

        return new PasskeyRegistration(
            $passkey->credentialId,
            $this->proofs->properties($passkey->observed),
            new ProofBinding($owner->type, $owner->key, $binding->application, self::signIn($binding), Purpose::ENROLLMENT),
        );
    }

    /**
     * The binding's session key as a string.
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
