<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Log\Context\Repository;
use SineMacula\Laravel\Authentication\Events\EventContext;

/**
 * A `laravel-authentication` caller as plain values (IAM-9.7): the guard it is
 * held on, its identity's type and identifier, its principal's type and
 * identifier, its active tenant's identifier and its session's identifier, each
 * as `laravel-authentication` snapshots it for its own events (`EventContext`),
 * so the records it fills name the same people a mapper's do.
 *
 * It is what `CallerContextContributor` fills a record from, read from the
 * guard holding the caller (`HeldCaller`) or, in a queued job, carried into the
 * job from whoever dispatched it (`CarryCallerIntoJobs`), under one hidden
 * Context key (`KEY`), as scalars only. A job reads it back from its payload,
 * so nothing carried is trusted: an envelope that is missing, partial or
 * malformed is no caller, never an exception, and nothing is resolved from it.
 * Hidden Context stays out of the logs, but travels in the queue payload
 * unencrypted, as audit-log's own carried actor does: it holds identifiers
 * only, never a token, a key or any other secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallerSnapshot
{
    /** @var string The hidden Context key the caller is carried into a job under. */
    public const string KEY = 'iam.audit.caller';

    /** @var list<string> The parts a caller is carried with, each a string or `null`. */
    private const array PARTS = ['guard', 'identity_type', 'identity_id', 'principal_type', 'principal_id', 'tenant_id', 'session_id'];

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  string  $identityType
     * @param  string  $identityId
     * @param  ?string  $principalType
     * @param  ?string  $principalId
     * @param  ?string  $tenantId
     * @param  ?string  $sessionId
     */
    public function __construct(

        /** The name of the guard holding the caller. */
        public string $guard,

        /** The identity's morph class, or its class name. */
        public string $identityType,

        /** The identity's auth identifier. */
        public string $identityId,

        /** The principal's morph class, or its class name, if any. */
        public ?string $principalType = null,

        /** The principal's identifier, if any. */
        public ?string $principalId = null,

        /** The active tenant's tenant identifier, if any. */
        public ?string $tenantId = null,

        /** The session's identifier, if any. */
        public ?string $sessionId = null,
    ) {}

    /**
     * The caller an event context describes, or `null` when it names no guard
     * or no identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return ?self
     */
    public static function of(EventContext $context): ?self
    {
        return self::fromParts([
            'guard'          => $context->guard,
            'identity_type'  => $context->identityType,
            'identity_id'    => $context->identityId,
            'principal_type' => $context->principalType,
            'principal_id'   => $context->principalId,
            'tenant_id'      => $context->tenantId,
            'session_id'     => $context->sessionId,
        ]);
    }

    /**
     * The caller the Context carries, or `null` when its envelope is missing,
     * partial or malformed: no map, a part missing or neither a string nor
     * `null`, or no guard, identity type or identity identifier.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @return ?self
     */
    public static function carriedIn(Repository $context): ?self
    {
        $parts = self::partsCarriedIn($context);

        return $parts === null ? null : self::fromParts($parts);
    }

    /**
     * Stop the Context carrying a caller, leaving everything else in it.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @return void
     */
    public static function forgetIn(Repository $context): void
    {
        $context->forgetHidden(self::KEY);
    }

    /**
     * Carry the caller in the Context, as scalars, under its one hidden key.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @return void
     */
    public function carryInto(Repository $context): void
    {
        $context->addHidden(self::KEY, [
            'guard'          => $this->guard,
            'identity_type'  => $this->identityType,
            'identity_id'    => $this->identityId,
            'principal_type' => $this->principalType,
            'principal_id'   => $this->principalId,
            'tenant_id'      => $this->tenantId,
            'session_id'     => $this->sessionId,
        ]);
    }

    /**
     * The caller the parts name, every one of them given, or `null` when they
     * name no guard, no identity type or no identity identifier.
     *
     * @param  array<string, ?string>  $parts
     * @return ?self
     */
    private static function fromParts(array $parts): ?self
    {
        ['guard' => $guard, 'identity_type' => $type, 'identity_id' => $id] = $parts;

        if ($guard === null || $type === null || $id === null) {
            return null;
        }

        return new self($guard, $type, $id, $parts['principal_type'], $parts['principal_id'], $parts['tenant_id'], $parts['session_id']);
    }

    /**
     * Each part the Context carries, a part missing being `null`; `null` when
     * the envelope is no map or a part is neither a string nor `null`.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @return ?array<string, ?string>
     */
    private static function partsCarriedIn(Repository $context): ?array
    {
        $carried = $context->getHidden(self::KEY);

        if (!is_array($carried)) {
            return null;
        }

        $parts = [];

        foreach (self::PARTS as $part) {

            $value = $carried[$part] ?? null;

            if ($value !== null && !is_string($value)) {
                return null;
            }

            $parts[$part] = $value;
        }

        return $parts;
    }
}
