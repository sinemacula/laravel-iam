<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason as AuthenticationFailureReason;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorResult;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding as AuthenticationBinding;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * MFA's passkey gateway, running a passkey factor's ceremonies through
 * `laravel-authentication`'s passkeys (IAM-3.10).
 *
 * An assertion is requested with `PasskeyService::factorOptions()` and verified
 * with `verifyFactor()`, on the guard the binding's application names, bound to
 * the same identity, sign-in and purpose (the purposes translate one to one),
 * and limited to the credentials MFA allows, which `laravel-authentication`
 * narrows to the identity's own passkeys on the guard's relying party. The
 * options handed out are `CeremonyOptions::toArray()`: `challenge` (the id of
 * the challenge), `options` (for the browser) and `expires_at`. The response
 * handed back is `['challenge' => <that id>, 'credential' => <the browser's
 * PublicKeyCredential, as an array or its JSON>]`; anything else does not
 * verify. A verified assertion is MFA's, with the credential it made, the
 * properties its own authenticator data showed, never what was asked for, and
 * the challenge it answered. MFA hands the gateway no client, so
 * `verifyFactor()` is handed one of which nothing is known
 * (`Translation\ClientTranslator::unknown()`), never one read from a request,
 * and `laravel-authentication`'s `PasskeyUsed` event names no client.
 *
 * `laravel-authentication` concedes nothing on the way and counts nothing: MFA
 * counts every failure. Its reasons cross as MFA's: a challenge that is no
 * longer live (unknown, used or expired, which it does not tell apart) is
 * `expired`, and every other failure, a counter that went backwards included,
 * is `invalid_code`. An empty allowlist, a response without a challenge or a
 * credential, and an assertion made by a credential the allowlist does not name
 * never verify. A request that would allow none of the identity's passkeys is
 * refused with an `OperationRefusedException` (`not_found`), as the browser
 * would otherwise offer any credential it holds; so is a binding that names
 * another identity.
 *
 * `laravel-authentication` keeps no public read of an identity's credential ids
 * (its passkey summaries leave them out), so the identity's registered passkeys
 * are listed as MFA's own passkey factors' credentials. They match the passkeys
 * `laravel-authentication` holds while its passkey factor gate is this
 * package's, which is mandatory and bound while MFA's capability switch is on:
 * the factor is made and removed in the same transaction as the passkey. A
 * factor whose passkey went any other way still cannot be asserted: no ceremony
 * is started for it. Passkeys are available whenever this adapter is bound,
 * which is only while an MFA application offers them; a guard with no valid
 * relying party fails closed when its ceremony runs.
 *
 * An application that names no `jwt` guard of `laravel-authentication`'s, and
 * an identity it does not sign in, cannot be resolved and throw
 * `UnresolvedReferenceException` (IAM-8.2). It holds nothing between calls
 * (IAM-8.1).
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
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     */
    public function __construct(

        /** Resolves `laravel-authentication`'s passkey service for a guard. */
        private AuthFactory $auth,

        /** Resolves the guard an application names and the identity MFA asks about. */
        private CurrentSession $sessions,

        /** Translates the purposes and the observed properties. */
        private ProofTranslator $proofs,
    ) {}

    /**
     * Whether passkeys can be used as a factor: always, while this adapter is
     * bound.
     *
     * @return bool
     */
    #[\Override]
    public function isAvailable(): bool
    {
        return true;
    }

    /**
     * The credential ids of the identity's registered passkeys, read as its
     * passkey factors' credentials.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return list<string>
     */
    #[\Override]
    public function credentialIds(MultiFactorAuthenticatable $identity): array
    {
        $credentials = [];

        foreach ($identity->authFactors()->get() as $factor) {

            $credential = $factor->getType() === PasskeySeams::TYPE ? $factor->getCredentialReference() : null;

            if ($credential === null || in_array($credential, $credentials, true)) {
                continue;
            }

            $credentials[] = $credential;
        }

        return $credentials;
    }

    /**
     * Request an assertion from the identity's passkeys among the credentials
     * given, through `laravel-authentication`'s factor ceremony.
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
     * Verify the client's response to the assertion request through
     * `laravel-authentication`'s factor ceremony, limited to the credentials
     * given, and return what it observed or why it does not verify.
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
     * MFA's failure reason for `laravel-authentication`'s: a ceremony whose
     * challenge expired, or is no live challenge of the binding, is `expired`,
     * one already answered `replayed`, and every other failure `invalid_code`.
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
     * MFA's assertion for what `laravel-authentication` verified, when the
     * credential that made it is one allowed, or why it does not verify.
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
     * The identity MFA asks about, as `laravel-authentication`'s, refused
     * unless the binding names it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function identity(MultiFactorAuthenticatable $identity, ProofBinding $binding): Identity
    {
        $owner = $this->sessions->identity($identity);

        return IdentityReference::of($owner)->owns($binding) ? $owner : throw self::refused('The ceremony is bound to another identity.');
    }

    /**
     * `laravel-authentication`'s binding of the ceremony: the same identity,
     * application, sign-in and purpose.
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
     * `laravel-authentication`'s passkey service for the guard the application
     * names, when it is a declared guard of the `jwt` driver.
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
     * The refusal of a ceremony no passkey of the identity's could answer, with
     * the detail for the logs.
     *
     * @param  string  $detail
     * @return \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function refused(string $detail): OperationRefusedException
    {
        return new OperationRefusedException(FailureReason::NOT_FOUND, $detail);
    }
}
