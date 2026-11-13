<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Mappers;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Events\SystemOverrideUsed;
use SineMacula\Laravel\Authorization\Support\Reference as AuthorizationReference;
use SineMacula\Laravel\Iam\Audit\Correlation;
use SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;

/**
 * Records laravel-authorization's decisions worth keeping and every change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthorizationEventMapper implements EventMapper
{
    /** @var array<string, \SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity> The code of each change, by its operation identifier. */
    private const array CODES = [
        'role.created'                       => AuthorizationActivity::ROLE_CREATED,
        'role.updated'                       => AuthorizationActivity::ROLE_UPDATED,
        'role.deleted'                       => AuthorizationActivity::ROLE_DELETED,
        'role.exclusion.declared'            => AuthorizationActivity::ROLE_EXCLUSION_DECLARED,
        'role.exclusion.removed'             => AuthorizationActivity::ROLE_EXCLUSION_REMOVED,
        'permission.created'                 => AuthorizationActivity::PERMISSION_CREATED,
        'permission.updated'                 => AuthorizationActivity::PERMISSION_UPDATED,
        'permission.deleted'                 => AuthorizationActivity::PERMISSION_DELETED,
        'policy.created'                     => AuthorizationActivity::POLICY_CREATED,
        'policy.updated'                     => AuthorizationActivity::POLICY_UPDATED,
        'policy.deleted'                     => AuthorizationActivity::POLICY_DELETED,
        'role.permission.granted'            => AuthorizationActivity::PERMISSION_GRANTED,
        'role.permission.revoked'            => AuthorizationActivity::PERMISSION_REVOKED,
        'role.permission.expired'            => AuthorizationActivity::GRANT_EXPIRED,
        'role.permission.expiry_changed'     => AuthorizationActivity::GRANT_EXPIRY_CHANGED,
        'identity.role.assigned'             => AuthorizationActivity::ROLE_ASSIGNED,
        'identity.role.revoked'              => AuthorizationActivity::ROLE_UNASSIGNED,
        'identity.role.expired'              => AuthorizationActivity::GRANT_EXPIRED,
        'identity.role.expiry_changed'       => AuthorizationActivity::GRANT_EXPIRY_CHANGED,
        'identity.permission.granted'        => AuthorizationActivity::PERMISSION_ASSIGNED,
        'identity.permission.revoked'        => AuthorizationActivity::PERMISSION_UNASSIGNED,
        'identity.permission.expired'        => AuthorizationActivity::GRANT_EXPIRED,
        'identity.permission.expiry_changed' => AuthorizationActivity::GRANT_EXPIRY_CHANGED,
        'identity.policy.attached'           => AuthorizationActivity::POLICY_ATTACHED,
        'identity.policy.detached'           => AuthorizationActivity::POLICY_DETACHED,
        'identity.policy.expired'            => AuthorizationActivity::GRANT_EXPIRED,
        'identity.policy.expiry_changed'     => AuthorizationActivity::GRANT_EXPIRY_CHANGED,
        'identity.boundary.set'              => AuthorizationActivity::BOUNDARY_SET,
        'identity.boundary.removed'          => AuthorizationActivity::BOUNDARY_REMOVED,
        'guardrail.set'                      => AuthorizationActivity::GUARDRAIL_SET,
        'guardrail.removed'                  => AuthorizationActivity::GUARDRAIL_REMOVED,
        'resource.policy.attached'           => AuthorizationActivity::RESOURCE_POLICY_ATTACHED,
        'resource.policy.detached'           => AuthorizationActivity::RESOURCE_POLICY_DETACHED,
    ];

    /** @var array<string, string> The kind of grant each expiry, or change to one, is about. */
    private const array GRANTS = [
        'identity.role.expired'              => 'role',
        'identity.role.expiry_changed'       => 'role',
        'identity.permission.expired'        => 'permission',
        'identity.permission.expiry_changed' => 'permission',
        'identity.policy.expired'            => 'policy',
        'identity.policy.expiry_changed'     => 'policy',
        'role.permission.expired'            => 'role_permission',
        'role.permission.expiry_changed'     => 'role_permission',
    ];

    /** @var array<string, string> The details kept under another name, by that name. */
    private const array RENAMED = [
        'include_subtree'          => 'scope.include_subtree',
        'system'                   => 'is_system',
        'document_version'         => 'document.version',
        'document_digest'          => 'document.digest',
        'previous_document_digest' => 'previous_document.digest',
        'previous_policy'          => 'previous',
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $tenants
     */
    public function __construct(

        /** Names each tenant by the identifier the access policy reads it by. */
        private TenantTranslator $tenants,
    ) {}

    /**
     * Describe the event on the record, or skip it.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord
    {
        return match (true) {
            $event instanceof DecisionEvaluated     => $this->decision($event, $record),
            $event instanceof AuthorizationMutation => $this->change($event, $record),
            $event instanceof SystemOverrideUsed    => $this->override($event, $record),
            default                                 => null,
        };
    }

    /**
     * Describe a decision worth a record, written once its transaction ends.
     *
     * @param  \SineMacula\Laravel\Authorization\Events\DecisionEvaluated  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function decision(DecisionEvaluated $event, PendingRecord $record): ?PendingRecord
    {
        $code = self::decisionCode($event);

        if ($code === null) {
            return null;
        }

        Snapshot::describe($record->afterTransaction(), $code, self::present([
            'action'      => $event->action,
            'resource'    => $event->resource,
            'application' => $event->application,
            'policies'    => array_map(static fn (StatementReference $statement): string => $statement->toString(), $event->statements),
            'activations' => $event->activations,
            'effect'      => $event->effect->value,
            'reason'      => $event->reason?->value,
        ]));

        self::attributeDecision($record, $event, $code === AuthorizationActivity::ACCESS_PREVIEWED);

        if ($code === AuthorizationActivity::ACCESS_DENIED) {
            $record->denied($event->reason?->value);
        }

        return $record->forTenant($this->tenantOf($event->tenant));
    }

    /**
     * Name a preview's previewer and principal, else the identity as principal.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @param  \SineMacula\Laravel\Authorization\Events\DecisionEvaluated  $event
     * @param  bool  $previewed
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function attributeDecision(PendingRecord $record, DecisionEvaluated $event, bool $previewed): void
    {
        $principal = self::reference($event->subject);
        $person    = self::reference($event->identity) ?? $principal;
        $about     = $previewed ? $principal           ?? $person : $person;

        if ($about !== null) {
            $record->on($about);
        }

        if ($previewed) {
            $record->by(self::reference($event->previewer));

            return;
        }

        $record->by($person)->asPrincipal($principal);
    }

    /**
     * The code a decision is recorded under, or null for one not recorded.
     *
     * @param  \SineMacula\Laravel\Authorization\Events\DecisionEvaluated  $event
     * @return ?\SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity
     */
    private static function decisionCode(DecisionEvaluated $event): ?AuthorizationActivity
    {
        return match (true) {
            $event->previewer !== null                                     => AuthorizationActivity::ACCESS_PREVIEWED,
            !$event->isAllowed()                                           => AuthorizationActivity::ACCESS_DENIED,
            $event->usedBreakGlass                                         => AuthorizationActivity::BREAK_GLASS_USED,
            $event->reportedBecause() === DecisionReport::SENSITIVE_ACTION => AuthorizationActivity::ACCESS_ALLOWED,
            default                                                        => null,
        };
    }

    /**
     * Describe a change and cover the grantees it altered beyond its subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function change(AuthorizationMutation $event, PendingRecord $record): ?PendingRecord
    {
        $code = self::CODES[$event->operation()] ?? null;

        if ($code === null) {
            return null;
        }

        Snapshot::describe($record, $code, self::properties($event));

        $about = self::reference($event->subject());

        self::attribute($record, $event->operationId(), $event->actor(), $event->actorIdentity());
        $this->place($record, $about, $event->tenant());

        $covered = array_filter(
            array_map(self::reference(...), $event->grantees()),
            static fn (?Reference $grantee): bool => $grantee !== null && $grantee->toArray() !== $about?->toArray(),
        );

        return $covered === [] ? $record : $record->covering($covered);
    }

    /**
     * The change's details under the names its code keeps them by.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation  $event
     * @return array<string, mixed>
     */
    private static function properties(AuthorizationMutation $event): array
    {
        $details = $event->auditProperties();
        $type    = $details['resource_type'] ?? null;
        $renamed = array_map(static fn (string $key): mixed => $details[$key] ?? null, self::RENAMED);

        return self::present([
            ...$details,
            ...$renamed,
            'trusted'          => $event->isTrusted(),
            'application'      => $event->application(),
            'grant'            => self::GRANTS[$event->operation()] ?? null,
            'changes'          => self::changedFields($details),
            'resource_type'    => is_string($type) ? References::type($type) : null,
            'grantee_count'    => count($event->grantees()),
            'permission_count' => self::countOf($details['permissions'] ?? null),
            'role_count'       => self::countOf($details['roles'] ?? null),
        ]);
    }

    /**
     * Describe a system record changed through `forceSystem()`.
     *
     * @param  \SineMacula\Laravel\Authorization\Events\SystemOverrideUsed  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function override(SystemOverrideUsed $event, PendingRecord $record): PendingRecord
    {
        $call = $event->operation;

        Snapshot::describe($record, AuthorizationActivity::SYSTEM_OVERRIDE_USED, [
            'trusted'             => $call->isTrusted,
            'name'                => $event->name,
            'protected_operation' => $event->protectedOperation,
        ]);

        self::attribute($record, $call->id, $call->actor, $call->identity);

        return $this->place($record, self::reference($event->record), $event->tenant);
    }

    /**
     * Correlate the record with its call and name the call's actor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @param  string  $operationId
     * @param  ?\SineMacula\Laravel\Authorization\Support\Reference  $actor
     * @param  ?\SineMacula\Laravel\Authorization\Support\Reference  $identity
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function attribute(PendingRecord $record, string $operationId, ?AuthorizationReference $actor, ?AuthorizationReference $identity): void
    {
        $correlation = Correlation::authorizationOperation($operationId);

        if ($correlation !== null) {
            $record->correlatedWith($correlation);
        }

        $principal = self::reference($actor);
        $person    = self::reference($identity);

        $record->by($person ?? $principal)->asPrincipal($person === null ? null : $principal);
    }

    /**
     * Name what the change is about and the tenant it holds in.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $about
     * @param  ?\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function place(PendingRecord $record, ?Reference $about, ?AuthorizationReference $tenant): PendingRecord
    {
        if ($about !== null) {
            $record->on($about);
        }

        return $record->forTenant($this->tenantOf($tenant));
    }

    /**
     * The tenant's identifier, once its key resolves back to the same tenant.
     *
     * @param  ?\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private function tenantOf(?AuthorizationReference $tenant): ?Reference
    {
        if ($tenant === null) {
            return null;
        }

        try {
            return References::tenant($this->tenants->idOf($tenant));
        } catch (UnresolvedReferenceException) {
            return null;
        }
    }

    /**
     * The names of the fields an update changed, never their values.
     *
     * @param  array<string, mixed>  $details
     * @return list<string>
     */
    private static function changedFields(array $details): array
    {
        $names = array_map(
            static fn (string $key): string => explode('.', $key)[2],
            preg_grep('/^changes\.[^.]+\.[^.]+/', array_keys($details)) ?: [],
        );

        $names = array_unique($names);

        sort($names, SORT_STRING);

        return $names;
    }

    /**
     * The length of a list detail; null when the event has none.
     *
     * @param  mixed  $list
     * @return ?int
     */
    private static function countOf(mixed $list): ?int
    {
        return is_array($list) ? count($list) : null;
    }

    /**
     * The properties less any that is null.
     *
     * @param  array<string, mixed>  $properties
     * @return array<string, mixed>
     */
    private static function present(array $properties): array
    {
        return array_filter($properties, static fn (mixed $value): bool => $value !== null);
    }

    /**
     * The reference read through the morph map; null for none.
     *
     * @param  ?\SineMacula\Laravel\Authorization\Support\Reference  $reference
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function reference(?AuthorizationReference $reference): ?Reference
    {
        return $reference === null ? null : References::of($reference->type, $reference->id);
    }
}
