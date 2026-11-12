<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Events\EventSubject;
use SineMacula\Laravel\Mfa\Support\IdentityType;

/**
 * MFA's event context, filled from the subject MFA hands it (IAM-3.12), each
 * value a scalar, never a model, a secret or a full destination:
 *
 * - the identity the event is about, by its type (its morph class, or its class
 *   name) and its key, as MFA records its owner;
 * - the client's IP address and user agent, as MFA hands them
 *   (`EventSubject::$client`), never read from a request;
 * - the session, the principal it acts as and the tenant it is active in, of
 *   the sign-in the operation was bound to, only when MFA names both the
 *   sign-in (`EventSubject::$signInId`) and the application it ran through, and
 *   that sign-in is one of the identity's sessions on the guard the application
 *   names.
 *
 * The sign-in is read by its key, as `CurrentSession::named()` reads it:
 * through the identity's own `sessions()` relation on the write connection, so
 * another identity's session, another guard's, an unknown key and one that
 * cannot be one of the session model's are none, never the guard's current
 * session or anything a request carries. The principal is read from the session
 * row's own columns, with no query of its own. A sign-in that is none, an
 * application that is no session guard, and an identity
 * `laravel-authentication` does not sign in leave the session, the principal
 * and the tenant unknown (`null`), as an event MFA names no sign-in for does
 * (an operator's action, a lockout): the resolver only describes an event, so
 * it never throws for them. An audit record that carries none of them is filled
 * from `laravel-authentication`'s caller by the audit trail's ambient context
 * (IAM-9.7).
 *
 * The event's application is MFA's to name: it writes the one the operation ran
 * through over whatever the resolver answers. It holds nothing between calls
 * (IAM-8.1).
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
            ...self::principalOf($session),
            'tenant_id'  => $session->getTenantId(),
            'session_id' => $reference,
        ];
    }

    /**
     * The principal the session acts as, by the type and key its row records
     * (`null` while it acts as none), read without a query.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return array<string, int|string|null>
     */
    private static function principalOf(Session $session): array
    {
        return $session instanceof EloquentSession && $session instanceof Model ? self::recordedPrincipal($session) : [];
    }

    /**
     * The principal's type and key, as the session's row records them.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return array<string, int|string|null>
     */
    private static function recordedPrincipal(EloquentSession&Model $session): array
    {
        $principal = $session->principal();
        $type      = $session->getAttribute($principal->getMorphType());

        return [
            'principal_type' => is_string($type) ? $type : null,
            'principal_id'   => EventContext::scalarKey($session->getAttribute($principal->getForeignKeyName())),
        ];
    }
}
