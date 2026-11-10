<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Mappers;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Events\Guardrail\GuardrailRemoved;
use SineMacula\Laravel\Authorization\Events\Guardrail\GuardrailSet;
use SineMacula\Laravel\Authorization\Events\Identity\BoundaryRemoved;
use SineMacula\Laravel\Authorization\Events\Identity\BoundarySet;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpired;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyDetached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpired;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpired;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Events\Permission\Created as PermissionCreated;
use SineMacula\Laravel\Authorization\Events\Permission\Deleted as PermissionDeleted;
use SineMacula\Laravel\Authorization\Events\Permission\Updated as PermissionUpdated;
use SineMacula\Laravel\Authorization\Events\Policy\Created as PolicyCreated;
use SineMacula\Laravel\Authorization\Events\Policy\Deleted as PolicyDeleted;
use SineMacula\Laravel\Authorization\Events\Policy\Updated as PolicyUpdated;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyAttached as ResourcePolicyAttached;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyDetached as ResourcePolicyDetached;
use SineMacula\Laravel\Authorization\Events\Role\Created as RoleCreated;
use SineMacula\Laravel\Authorization\Events\Role\Deleted as RoleDeleted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpired as RolePermissionExpired;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpiryChanged as RolePermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted as RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked as RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Role\Updated as RoleUpdated;
use SineMacula\Laravel\Authorization\Events\SystemOverrideUsed;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference as AuthorizationReference;
use SineMacula\Laravel\Iam\Audit\Correlation;
use SineMacula\Laravel\Iam\Audit\DeferredRefusals;
use SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;

/**
 * Records `laravel-authorization`'s events (`AuthorizationEvent`) in audit-log,
 * from each event alone (IAM-9.1, IAM-9.2, IAM-9.4).
 *
 * `laravel-authorization` reports every check (`DecisionEvaluated`), allows
 * included, and the hard denial `authorize()` throws a second time
 * (`AuthorizationFailed`). Of the decisions, three are recorded, each once: a
 * preview (`access_previewed`, by the previewer, about the principal previewed,
 * never as impersonation), a check a break-glass grant allowed
 * (`break_glass_used`), and a denial (`access_denied`, denied with the
 * decision's reason code). A denial as `insufficient_authentication` is one
 * too, told apart by its reason: on the caller's own session it asks for a
 * stronger proof, which MFA's step-up answers, but on no session (a job's or a
 * command's subject, or `Authorization::for()` given a principal alone) nothing
 * can step it up, so it is a plain refusal, and the event does not say which it
 * was. Any other allow, and `AuthorizationFailed`, which repeats the
 * `DecisionEvaluated` it follows, are skipped, so one denial is one record. A
 * decision's record keeps the action, the resource as the check named it, the
 * application and the statements that decided it, each by its policy's key,
 * never a context value; its actor is the decision's identity, else its
 * subject, as the principal it acted as, both explicitly none for a guest; its
 * subject is that identity, except a preview's, which is the principal
 * previewed, since one person may hold several; and its tenant the decision's,
 * explicitly none for a platform check.
 *
 * A decision is reported as it is made, inside whatever transaction is open,
 * which may roll back; a denial is a fact even then. So a decision to be
 * recorded while a transaction is open on audit-log's storage connection is
 * handed to `DeferredRefusals`, and recorded once that transaction has ended,
 * whichever way it ended.
 *
 * Every change (a role, permission or policy created, updated or deleted; a
 * grant, boundary or guardrail set or removed; a grant expired or its expiry
 * changed; a policy attached to or detached from a resource; a system override)
 * is recorded under its own code, correlated with every other event of the same
 * call (`authorization:{operation_id}`). Its actor is the call's: the identity
 * behind the acting principal, as that principal, or the reference a trusted
 * command named, and explicitly no one for system work (an expiry the pruner
 * found, a write through a model outside the services), so the contributors
 * never fill in an unrelated caller. Its subject is what changed (the role,
 * permission or policy, the grantee of a grant or boundary, the guardrail's
 * policy, the resource policy, the overridden record), and its tenant the one
 * the change holds in, explicitly none for a platform-wide one. A deletion that
 * took grants from grantees carries their manifest, as audit-log's bulk record
 * does (`GranteeManifests`).
 *
 * References are read through the morph map (`Audit\References`). A tenant is
 * named by its identifier, as every other member's records name it and the
 * audit access policy scopes a viewer by it (`AuditAccessPolicyAdapter`): the
 * key `laravel-authorization` names it by, only once that key, resolved through
 * `laravel-authentication`'s tenant resolver as an identifier, names the same
 * tenant by type and key (`TenantTranslator::idOf()`). A tenant that does not
 * resolve back, keyed otherwise than by its identifier or not resolved at all,
 * is recorded with no tenant rather than its key, which may be another tenant's
 * identifier and would file the record in that tenant's trail: an entry with no
 * tenant is shown to no viewer scoped to tenants. It reads nothing but the
 * event, the morph map, audit-log's bounds and the tenant resolver, and keeps
 * nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthorizationEventMapper implements EventMapper
{
    /** @var array<class-string<\SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent>, \SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity> The code of each change. */
    private const array CODES = [
        RoleCreated::class                 => AuthorizationActivity::ROLE_CREATED,
        RoleUpdated::class                 => AuthorizationActivity::ROLE_UPDATED,
        RoleDeleted::class                 => AuthorizationActivity::ROLE_DELETED,
        PermissionCreated::class           => AuthorizationActivity::PERMISSION_CREATED,
        PermissionUpdated::class           => AuthorizationActivity::PERMISSION_UPDATED,
        PermissionDeleted::class           => AuthorizationActivity::PERMISSION_DELETED,
        PolicyCreated::class               => AuthorizationActivity::POLICY_CREATED,
        PolicyUpdated::class               => AuthorizationActivity::POLICY_UPDATED,
        PolicyDeleted::class               => AuthorizationActivity::POLICY_DELETED,
        RolePermissionGranted::class       => AuthorizationActivity::PERMISSION_GRANTED,
        RolePermissionRevoked::class       => AuthorizationActivity::PERMISSION_REVOKED,
        RolePermissionExpired::class       => AuthorizationActivity::GRANT_EXPIRED,
        RolePermissionExpiryChanged::class => AuthorizationActivity::GRANT_EXPIRY_CHANGED,
        RoleAssigned::class                => AuthorizationActivity::ROLE_ASSIGNED,
        RoleRevoked::class                 => AuthorizationActivity::ROLE_UNASSIGNED,
        RoleExpired::class                 => AuthorizationActivity::GRANT_EXPIRED,
        RoleExpiryChanged::class           => AuthorizationActivity::GRANT_EXPIRY_CHANGED,
        PermissionGranted::class           => AuthorizationActivity::PERMISSION_ASSIGNED,
        PermissionRevoked::class           => AuthorizationActivity::PERMISSION_UNASSIGNED,
        PermissionExpired::class           => AuthorizationActivity::GRANT_EXPIRED,
        PermissionExpiryChanged::class     => AuthorizationActivity::GRANT_EXPIRY_CHANGED,
        PolicyAttached::class              => AuthorizationActivity::POLICY_ATTACHED,
        PolicyDetached::class              => AuthorizationActivity::POLICY_DETACHED,
        PolicyExpired::class               => AuthorizationActivity::GRANT_EXPIRED,
        PolicyExpiryChanged::class         => AuthorizationActivity::GRANT_EXPIRY_CHANGED,
        BoundarySet::class                 => AuthorizationActivity::BOUNDARY_SET,
        BoundaryRemoved::class             => AuthorizationActivity::BOUNDARY_REMOVED,
        GuardrailSet::class                => AuthorizationActivity::GUARDRAIL_SET,
        GuardrailRemoved::class            => AuthorizationActivity::GUARDRAIL_REMOVED,
        ResourcePolicyAttached::class      => AuthorizationActivity::RESOURCE_POLICY_ATTACHED,
        ResourcePolicyDetached::class      => AuthorizationActivity::RESOURCE_POLICY_DETACHED,
        SystemOverrideUsed::class          => AuthorizationActivity::SYSTEM_OVERRIDE_USED,
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Audit\DeferredRefusals  $refusals
     * @param  \SineMacula\Laravel\Iam\Audit\Mappers\GranteeManifests  $manifests
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $tenants
     */
    public function __construct(

        /** Holds a decision reported inside a transaction until the outermost one has ended. */
        private DeferredRefusals $refusals,

        /** Carries a deletion's grantees as the record's manifest. */
        private GranteeManifests $manifests,

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
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     */
    #[\Override]
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord
    {
        if ($event instanceof DecisionEvaluated) {
            return $this->decision($event, $record);
        }

        $code   = $event instanceof AuthorizationEvent ? (self::CODES[$event::class] ?? null) : null;
        $change = $code === null ? null : AuthorizationChange::of($event);

        return $change === null ? null : $this->change($change, $code, $record);
    }

    /**
     * Describe a decision worth a record, or skip it; one reported inside a
     * transaction on the storage connection is held until that has ended.
     *
     * @param  \SineMacula\Laravel\Authorization\Events\DecisionEvaluated  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function decision(DecisionEvaluated $event, PendingRecord $record): ?PendingRecord
    {
        $code = self::decisionCode($event);

        if ($code === null || $this->refusals->defers($event)) {
            return null;
        }

        Snapshot::describe($record, $code, self::present([
            'action'      => $event->action,
            'resource'    => $event->resource,
            'application' => $event->application,
            'policies'    => array_map(static fn (StatementReference $statement): string => $statement->toString(), $event->statements),
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
     * Name the decision's actor and subject on the record: a preview's actor is
     * the previewer and its subject the principal previewed, else the identity,
     * since one person may hold several principals; any other decision's actor
     * is its identity, else its subject, as that principal, and its subject the
     * same person.
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
     * The code a decision is recorded under, or `null` for one that is not
     * recorded: a preview, a break-glass grant used, or any denial.
     *
     * @param  \SineMacula\Laravel\Authorization\Events\DecisionEvaluated  $event
     * @return ?\SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity
     */
    private static function decisionCode(DecisionEvaluated $event): ?AuthorizationActivity
    {
        return match (true) {
            $event->previewer !== null => AuthorizationActivity::ACCESS_PREVIEWED,
            $event->isAllowed()        => $event->usedBreakGlass ? AuthorizationActivity::BREAK_GLASS_USED : null,
            default                    => AuthorizationActivity::ACCESS_DENIED,
        };
    }

    /**
     * Describe a change: its code, what it keeps, the call that made it, what
     * changed and where, and a deletion's grantees.
     *
     * @param  \SineMacula\Laravel\Iam\Audit\Mappers\AuthorizationChange  $change
     * @param  \SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity  $code
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     */
    private function change(AuthorizationChange $change, AuthorizationActivity $code, PendingRecord $record): PendingRecord
    {
        Snapshot::describe($record, $code, ['trusted' => $change->operation->isTrusted, ...$change->properties]);

        $correlation = Correlation::authorizationOperation($change->operation->id);

        if ($correlation !== null) {
            $record->correlatedWith($correlation);
        }

        $subject = self::reference($change->subject);

        if ($subject !== null) {
            $record->on($subject);
        }

        self::attribute($record, $change->operation);

        $record->forTenant($this->tenantOf($change->tenant));

        return $this->manifests->carry($record, $change->grantees);
    }

    /**
     * Name the call's actor on the record: the identity behind the acting
     * principal, as that principal; else the reference a trusted command named;
     * else explicitly no one.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function attribute(PendingRecord $record, Operation $operation): void
    {
        $principal = self::reference($operation->actor);
        $identity  = self::reference($operation->identity);

        $record->by($identity ?? $principal)->asPrincipal($identity === null ? null : $principal);
    }

    /**
     * The tenant audit-log files the record under: the identifier of the tenant
     * `laravel-authorization` names, once its key resolves back to that same
     * tenant (`TenantTranslator::idOf()`); none for a platform-wide one, and
     * none for one that does not resolve back, rather than its key, which would
     * name another tenant's trail.
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
     * The properties given, less any that is `null`: a value the event does not
     * have is left out.
     *
     * @param  array<string, mixed>  $properties
     * @return array<string, mixed>
     */
    private static function present(array $properties): array
    {
        return array_filter($properties, static fn (mixed $value): bool => $value !== null);
    }

    /**
     * The reference audit-log names a `laravel-authorization` reference by,
     * read through the morph map, or `null` for none.
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
