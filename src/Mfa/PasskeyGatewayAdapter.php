<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason as AuthenticationFailureReason;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorResult;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding as AuthenticationBinding;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * MFA's passkey gateway, running passkey factor ceremonies through
 * `laravel-authentication`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasskeyGatewayAdapter implements PasskeyGateway
{
    /** @var string The response's key the challenge's id is handed back under. */
    public const string CHALLENGE = 'challenge';

    /** @var string The response's key the browser's credential is handed back under. */
    public const string CREDENTIAL = 'credential';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     */
    public function __construct(

        /** Resolves `laravel-authentication`'s passkey service for a guard. */
        private AuthFactory $auth,

        /** Holds the MFA applications and the factor types each offers. */
        private Repository $config,

        /** Resolves the guard an application names and the identity MFA asks about. */
        private CurrentSession $sessions,

        /** Translates the purposes and the observed properties. */
        private ProofTranslator $proofs,
    ) {}

    /**
     * Always true: this is bound only while an application offers passkeys.
     *
     * @return bool
     */
    #[\Override]
    public function isAvailable(): bool
    {
        return true;
    }

    /**
     * The identity's passkey credential ids, if the guard offers passkeys.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function credentialIds(MultiFactorAuthenticatable $identity, string $application): array
    {
        if (!PasskeySeams::isOfferedBy($this->config, $application)) {
            return [];
        }

        return $this->passkeys($application)->credentialIds($this->sessions->identity($identity));
    }

    /**
     * Request an assertion from the identity's allowed passkeys.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  list<string>  $credentialIds
     * @return array<string, mixed>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    #[\Override]
    public function requestAssertion(MultiFactorAuthenticatable $identity, ProofBinding $binding, #[\SensitiveParameter] array $credentialIds): array
    {
        $owner   = $this->identity($identity, $binding);
        $options = $this->passkeys($binding->application)->factorOptions($owner, $this->binding($owner, $binding), $credentialIds);

        return $options?->toArray() ?? throw self::refused('None of the identity\'s passkeys is among the credentials allowed.');
    }

    /**
     * Verify the response against the allowed credentials, or say why it fails.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  list<string>  $credentialIds
     * @param  array<string, mixed>  $response
     * @return \SineMacula\Laravel\Mfa\Enums\FailureReason|\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    #[\Override]
    public function verifyAssertion(
        MultiFactorAuthenticatable $identity,
        ProofBinding $binding,
        #[\SensitiveParameter] array $credentialIds,
        #[\SensitiveParameter] array $response,
    ): FailureReason|PasskeyAssertion {
        $owner      = $this->identity($identity, $binding);
        $challenge  = $response[self::CHALLENGE]  ?? null;
        $credential = $response[self::CREDENTIAL] ?? null;

        if ($credentialIds === [] || !is_string($challenge) || $challenge === '' || (!is_array($credential) && !is_string($credential))) {
            return FailureReason::INVALID_CODE;
        }

        $result = $this->passkeys($binding->application)->verifyFactor($owner, $this->binding($owner, $binding), $challenge, $credential, ClientTranslator::unknown());

        return $this->assertionOf($result, $credentialIds, $challenge);
    }

    /**
     * MFA's failure reason for `laravel-authentication`'s ceremony failure.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Mfa\Enums\FailureReason
     */
    public static function reason(?AuthenticationFailureReason $reason): FailureReason
    {
        return match ($reason) {
            AuthenticationFailureReason::PASSKEY_CHALLENGE_EXPIRED,
            AuthenticationFailureReason::PASSKEY_CHALLENGE_INVALID => FailureReason::EXPIRED,
            AuthenticationFailureReason::PASSKEY_CHALLENGE_USED    => FailureReason::REPLAYED,
            default                                                => FailureReason::INVALID_CODE,
        };
    }

    /**
     * MFA's assertion, when an allowed credential made it, or why it fails.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorResult  $result
     * @param  list<string>  $credentialIds
     * @param  string  $challenge
     * @return \SineMacula\Laravel\Mfa\Enums\FailureReason|\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion
     *
     * @throws \InvalidArgumentException
     */
    private function assertionOf(PasskeyFactorResult $result, #[\SensitiveParameter] array $credentialIds, string $challenge): FailureReason|PasskeyAssertion
    {
        $assertion = $result->assertion;

        if ($assertion === null) {
            return self::reason($result->reason);
        }

        return in_array($assertion->credentialId, $credentialIds, true)
            ? new PasskeyAssertion($assertion->credentialId, $this->proofs->properties($assertion->observed), $challenge)
            : FailureReason::INVALID_CODE;
    }

    /**
     * The identity MFA asks about, refused unless the binding names it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function identity(MultiFactorAuthenticatable $identity, ProofBinding $binding): Identity
    {
        $owner = $this->sessions->identity($identity);

        return ProofOwner::of($owner)->owns($binding) ? $owner : throw self::refused('The ceremony is bound to another identity.');
    }

    /**
     * `laravel-authentication`'s binding of the ceremony.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofBinding
     *
     * @throws \InvalidArgumentException
     */
    private function binding(Identity $owner, ProofBinding $binding): AuthenticationBinding
    {
        return new AuthenticationBinding($owner, $binding->application, $binding->sessionId, $this->proofs->toAuthenticationPurpose($binding->purpose));
    }

    /**
     * The passkey service of the application's `jwt` guard.
     *
     * @param  string  $application
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyService
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function passkeys(string $application): PasskeyService
    {
        $auth = $this->auth;

        if (!$auth instanceof AuthManager) {
            throw UnresolvedReferenceException::forGuard($application);
        }

        $this->sessions->guard($application);

        return $auth->passkeys($application);
    }

    /**
     * The refusal of a ceremony no passkey of the identity's could answer.
     *
     * @param  string  $detail
     * @return \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function refused(string $detail): OperationRefusedException
    {
        return new OperationRefusedException(FailureReason::NOT_FOUND, $detail);
    }
}
