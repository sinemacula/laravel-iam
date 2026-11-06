<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\EventContext;

/**
 * MFA's event context, filled from `laravel-authentication`'s caller
 * (IAM-3.12), each value a scalar, never a model, a secret or a full
 * destination:
 *
 * - the identity the event is about, by its type (its morph class, or its class
 *   name) and its key, as MFA records its owner;
 * - the application, the guard that serves the request (as
 *   `ApplicationResolverAdapter` names it), when there is a request;
 * - the principal, by its type and key, the tenant the validated session
 *   records, and the session, by the reference MFA names its sign-in by, only
 *   when that guard holds a session of the identity the event is about, so
 *   nothing of whoever else the request serves (an administrator acting on
 *   another identity, say) is attributed to it, and no tenant the request
 *   merely claims or a trusted bind sets beside the session is either;
 * - the request's IP address and user agent, when there is a request.
 *
 * A value it does not know is `null`. It never throws for want of a request, a
 * guard of `laravel-authentication`'s, a session or a tenant, since it only
 * describes an event: a default guard that holds no sessions, or holds none of
 * the identity, describes no principal, tenant or session.
 *
 * It reads the guard's state as it stands, and not `Auth::caller()`, which is
 * kept for the rest of the request once asked, so an event fired before a
 * sign-in completes never leaves the application a stale caller. It runs no
 * query of its own, and holds nothing between calls: the guard is read on every
 * call (IAM-8.1).
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

        /** Resolves the guard that serves the request and the session it holds. */
        private CurrentSession $sessions,
    ) {}

    /**
     * The context an event about the identity, in the request, carries.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\Illuminate\Http\Request  $request
     * @return array<string, int|string|null>
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    public function resolve(?MultiFactorAuthenticatable $identity, ?Request $request): array
    {
        $guard = $request === null ? '' : trim($this->sessions->defaultGuard());

        $application = $guard    === '' ? null : $guard;
        $signIn      = $identity === null || $application === null ? [] : $this->signIn($identity, $application);

        return EventContext::allowlist([
            ...$signIn,
            'identity_type' => $identity === null ? null : self::typeOf($identity),
            'identity_id'   => EventContext::scalarKey($identity?->getAuthIdentifier()),
            'application'   => $application,
            'ip'            => $request?->ip(),
            'user_agent'    => $request?->userAgent(),
        ]);
    }

    /**
     * The principal, tenant and session of the identity's sign-in the guard
     * holds, or nothing when it holds none of the identity's, holds one acting
     * as no principal yet, or is no guard of `laravel-authentication`'s that
     * holds sessions.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return array<string, int|string|null>
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function signIn(MultiFactorAuthenticatable $identity, string $application): array
    {
        try {
            $session   = $this->sessions->current($identity, $application);
            $reference = SignIn::reference($session, $application);
            $principal = $this->sessions->guard($application)->principal();
        } catch (UnresolvedReferenceException) {
            return [];
        }

        return $principal === null ? [] : [
            'principal_type' => self::typeOf($principal),
            'principal_id'   => EventContext::scalarKey($principal->getPrincipalIdentifier()),
            'tenant_id'      => $session->getTenantId(),
            'session_id'     => $reference,
        ];
    }

    /**
     * The type an identity or a principal is recorded under: its morph class
     * for an Eloquent model, so an application's morph map is honoured, and its
     * class name otherwise.
     *
     * @param  object  $subject
     * @return string
     */
    private static function typeOf(object $subject): string
    {
        // @phpstan-ignore staticMethod.dynamicCall
        return $subject instanceof Model ? $subject->getMorphClass() : $subject::class;
    }
}
