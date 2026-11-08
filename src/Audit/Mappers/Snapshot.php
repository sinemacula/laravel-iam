<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Mappers;

use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\Authentication\Events\EventContext as AuthenticationContext;
use SineMacula\Laravel\Iam\Audit\Contracts\ListsProperties;
use SineMacula\Laravel\Iam\Audit\Mappers\Enums\Attribution;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Sso\Events\EventContext as SsoContext;

/**
 * Who and what a member's event is about, read from the event's own context
 * alone and translated to one shape for every member (IAM-9.5): the identity,
 * the principal and the tenant as references (`Audit\References`), the guard,
 * the session and the client.
 *
 * `laravel-authentication` names the guard; MFA and SSO name the application,
 * which in this package is the guard of the same name, so it stands for the
 * guard. SSO names the active tenant (`tenant_id`) and the connection's own
 * (`connection_tenant_id`): the record's tenant is the active one, else the
 * connection's, the tenant the activity happened in either way.
 *
 * `attribute()` writes it onto a record: the subject given, the actor as the
 * event's attribution says, and the principal and tenant beside it. An actor
 * taken from the event (the identity, explicitly no one, or an operator the
 * event names) is the record's whatever the contributors would fill, and so is
 * the principal and tenant of the identity's own action, explicitly none when
 * the event names none, so an unrelated caller's never lands on it. An actor
 * left to the contributors (`Attribution::CALLER`) leaves the principal to them
 * too, since it is the actor's, and a mapper keeps the event's own principal as
 * properties where it is what the activity was done to; the tenant is the
 * event's when it names one, the boundary the activity happened in. An
 * operator's principal is likewise left to the contributors. The guard, the
 * session and the client are filled before any contributor runs, so the event's
 * win over the request being served, which under a queue or a later commit may
 * be another's, and a part the event lacks is left for them.
 *
 * Audit-log offers a mapper no explicit setter of the guard, the session or the
 * client, only the fillers its own capture uses for the same, so they are
 * filled through those.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Snapshot
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $identity
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $principal
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  ?string  $guard
     * @param  ?string  $sessionId
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     */
    public function __construct(

        /** The identity the event is about. */
        public ?Reference $identity,

        /** The principal the identity acts as. */
        public ?Reference $principal,

        /** The tenant the activity happened in. */
        public ?Reference $tenant,

        /** The guard the activity ran under. */
        public ?string $guard,

        /** The session the event is about. */
        public ?string $sessionId,

        /** The client's IP address. */
        #[\SensitiveParameter]
        public ?string $ip,

        /** The client's user agent. */
        #[\SensitiveParameter]
        public ?string $userAgent,
    ) {}

    /**
     * The snapshot of a `laravel-authentication` event's context.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function ofAuthentication(AuthenticationContext $context): self
    {
        return new self(
            References::of($context->identityType, $context->identityId),
            References::of($context->principalType, $context->principalId),
            References::tenant($context->tenantId),
            $context->guard,
            $context->sessionId,
            $context->client->ip,
            $context->client->userAgent,
        );
    }

    /**
     * The snapshot of an MFA event's context.
     *
     * @param  array<string, int|string|null>  $context
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function ofMfa(array $context): self
    {
        return new self(
            References::of(self::text($context, 'identity_type'), $context['identity_id'] ?? null),
            References::of(self::text($context, 'principal_type'), $context['principal_id'] ?? null),
            References::tenant($context['tenant_id'] ?? null),
            self::text($context, 'application'),
            self::text($context, 'session_id'),
            self::text($context, 'ip'),
            self::text($context, 'user_agent'),
        );
    }

    /**
     * The snapshot of an SSO event's context.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function ofSso(SsoContext $context): self
    {
        return new self(
            References::of($context->identityMorphClass, $context->identityId),
            References::of($context->principalMorphClass, $context->principalId),
            References::tenant($context->tenantId ?? $context->connectionTenantId),
            $context->application,
            $context->sessionId,
            $context->ip,
            $context->userAgent,
        );
    }

    /**
     * Start the record of an event: its code, and of the properties it
     * describes itself with exactly those the code's definition keeps, so none
     * is carried only to be dropped. A code audit-log ships keeps none of them:
     * its few columns say it all.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @param  \BackedEnum  $code
     * @param  array<string, mixed>  $properties
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function describe(PendingRecord $record, \BackedEnum $code, #[\SensitiveParameter] array $properties): PendingRecord
    {
        $kept = $code instanceof ListsProperties ? array_intersect_key($properties, array_flip($code->properties())) : [];

        return $record->event($code)->withProperties($kept);
    }

    /**
     * Write the snapshot onto the record: the subject, the actor as the
     * attribution says or the operator given, the principal, the tenant, the
     * guard, the session and the client.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @param  \SineMacula\Laravel\Iam\Audit\Mappers\Enums\Attribution  $attribution
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $operator
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function attribute(PendingRecord $record, Attribution $attribution, ?Reference $subject, ?Reference $operator = null): PendingRecord
    {
        if ($subject !== null) {
            $record->on($subject);
        }

        if ($operator !== null) {
            $record->by($operator);
        } elseif ($attribution !== Attribution::CALLER) {
            $record->by($attribution === Attribution::SUBJECT ? $this->identity : null)->asPrincipal($this->principal)->forTenant($this->tenant);
        }

        if ($this->tenant !== null) {
            $record->forTenant($this->tenant);
        }

        $record->fillGuard($this->guard);
        $record->fillSession($this->sessionId);
        $record->fillClient($this->ip, $this->userAgent);

        return $record;
    }

    /**
     * The context's value of the key as text, or `null` when it holds none.
     *
     * @param  array<string, int|string|null>  $context
     * @param  string  $key
     * @return ?string
     */
    private static function text(array $context, string $key): ?string
    {
        $value = $context[$key] ?? null;

        return $value === null || $value === '' ? null : (string) $value;
    }
}
