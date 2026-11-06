<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\EventContext;

/**
 * MFA's event context, filled from the values MFA hands it (IAM-3.12), each a
 * scalar, never a model, a secret or a full destination:
 *
 * - the identity the event is about, by its type (its morph class, or its class
 *   name) and its key, as MFA records its owner;
 * - the client's IP address and user agent, as MFA hands them
 *   (`ClientContext`), never read from a request.
 *
 * MFA hands the resolver the identity and the client alone: no application and
 * no sign-in. The event's application is MFA's to name, and it writes the one
 * the operation ran on over whatever the resolver answers. The principal, the
 * tenant and the session are left unknown (`null`), never read from the guard:
 * the default guard's current session may be another application's than the one
 * the operation ran on, or serve an administrator, a console command or a
 * pruning acting on the identity, so attributing it would describe a sign-in
 * the event is not about. An audit record that carries none of them is filled
 * from `laravel-authentication`'s caller by the audit trail's ambient context
 * (IAM-9.7). Once MFA hands the resolver the operation's application and
 * sign-in (member gap), the event can name them from those values.
 *
 * An event MFA hands no client with names no IP address or user agent. It never
 * throws, since it only describes an event, reads no guard, session or request,
 * runs no query, and holds nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EventContextResolverAdapter implements EventContextResolver
{
    /**
     * The context of an event about the identity, served to the client.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return array<string, int|string|null>
     */
    #[\Override]
    public function resolve(?MultiFactorAuthenticatable $identity, ?ClientContext $client): array
    {
        return EventContext::allowlist([
            'identity_type' => $identity === null ? null : self::typeOf($identity),
            'identity_id'   => EventContext::scalarKey($identity?->getAuthIdentifier()),
            'ip'            => $client?->ip,
            'user_agent'    => $client?->userAgent,
        ]);
    }

    /**
     * The type an identity is recorded under: its morph class for an Eloquent
     * model, so an application's morph map is honoured, and its class name
     * otherwise.
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
