<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Events\EventSubject;
use SineMacula\Laravel\Mfa\Support\IdentityType;

/**
 * MFA's event context (IAM-3.12): the identity and client MFA hands over, and
 * the session, principal and tenant of the sign-in MFA names when it is one of
 * the identity's sessions on the application's guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EventContextResolverAdapter implements EventContextResolver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     */
    public function __construct(

        /** Reads the session the sign-in MFA names is. */
        private CurrentSession $sessions,
    ) {}

    /**
     * The context of an event about the subject.
     *
     * @param  \SineMacula\Laravel\Mfa\Events\EventSubject  $subject
     * @return array<string, int|string|null>
     *
     * @throws \Throwable
     */
    #[\Override]
    public function resolve(EventSubject $subject): array
    {
        $identity = $subject->identity;
        $client   = $subject->client;

        return EventContext::allowlist([
            ...$this->signIn($identity, $subject->application, $subject->signInId),
            'identity_type' => $identity === null ? null : IdentityType::of($identity),
            'identity_id'   => EventContext::scalarKey($identity?->getAuthIdentifier()),
            'ip'            => $client->ip,
            'user_agent'    => $client->userAgent,
        ]);
    }

    /**
     * The session, principal and tenant of the sign-in named, when it is one of
     * the identity's sessions on the application's guard, or nothing.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?string  $application
     * @param  ?string  $signIn
     * @return array<string, int|string|null>
     *
     * @throws \Throwable
     */
    private function signIn(?MultiFactorAuthenticatable $identity, ?string $application, ?string $signIn): array
    {
        if ($identity === null || $application === null || $signIn === null) {
            return [];
        }

        try {
            $session   = $this->sessions->named($identity, $application, $signIn);
            $reference = SignIn::reference($session, $application);
        } catch (UnresolvedReferenceException) {
            return [];
        }

        return [
            'principal_type' => $session->getPrincipalType(),
            'principal_id'   => $session->getPrincipalId(),
            'tenant_id'      => $session->getTenantId(),
            'session_id'     => $reference,
        ];
    }
}
