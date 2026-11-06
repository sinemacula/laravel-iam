<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * MFA's active tenant, read from the tenant `laravel-authentication`'s
 * validated session records (IAM-3.12): the session the guard the application
 * names holds for the identity, as the guard validated it for the request, its
 * recorded tenant id handed over as MFA's opaque tenant id. Never a tenant the
 * request claims, never the active tenant a trusted bind or a test sets on the
 * guard beside the session, and never an event's context.
 *
 * A session that acts in no tenant answers no tenant, as does a credential the
 * guard validated without a session (an access token that records none). An
 * identity that holds no validated session on the application in the request
 * answers none too: a sign-in judged before its session is written, which
 * `laravel-authentication` asks deliberately without a tenant and then holds to
 * the destination tenant's own authentication policy once a principal is
 * chosen, or a change to an identity the request does not serve. No session's
 * tenant applies to either, and refusing them would refuse every sign-in MFA
 * judges. An application that is no guard of `laravel-authentication`'s holding
 * sessions is a misconfiguration and throws `UnresolvedReferenceException` of
 * the kind `guard`, as does an identity whose key names nothing of the kind
 * `identity` (IAM-8.2), inside whatever transaction MFA opened, so it rolls
 * back.
 *
 * It reads the session the guard already holds and runs no query of its own, so
 * it takes no lock and cannot invert the lock order of the transaction it is
 * asked in. It holds nothing between calls: the guard is read on every call
 * (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ActiveTenantResolverAdapter implements ActiveTenantResolver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     */
    public function __construct(

        /** Resolves the application's guard and the session it holds. */
        private CurrentSession $sessions,
    ) {}

    /**
     * The tenant whose policy applies to the identity's session on the
     * application, as an opaque id, or `null` for none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function activeTenant(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        $guard = $this->sessions->guard($application);
        $asked = IdentityReference::of($identity);
        $owner = $guard->identity();

        if ($owner === null || !IdentityReference::of($owner)->is($asked)) {
            return null;
        }

        return $guard->session()?->getTenantId();
    }
}
