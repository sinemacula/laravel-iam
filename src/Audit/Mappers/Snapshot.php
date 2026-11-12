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
 * Who and what a member's event is about, read from its context alone and
 * written onto a record in one shape for every member (IAM-9.5).
 *
 * MFA's and SSO's application stands for the guard of the same name, and SSO's
 * tenant is the active one, else the connection's. An actor taken from the
 * event brings its principal and tenant, explicitly none when the event names
 * none; an actor left to the caller, or an operator, leaves the principal to
 * the contributors. The event's guard, session and client beat the
 * contributors'; a part the event names none of is left to them.
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
     * Start the record with the event's code and the properties it keeps.
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
     * Write the subject, actor, principal, tenant, guard, session and client.
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

        if ($this->guard !== null) {
            $record->viaGuard($this->guard);
        }

        if ($this->sessionId !== null) {
            $record->inSession($this->sessionId);
        }

        // Both at once, never mixing the event's client with the request's.
        if ($this->ip !== null || $this->userAgent !== null) {
            $record->fromClient($this->ip, $this->userAgent);
        }

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
