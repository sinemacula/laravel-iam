<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit\Mappers;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\BulkManifests;
use SineMacula\Laravel\AuditLog\Capture\CaptureSettings;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Stores\NullAuditStore;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
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
use SineMacula\Laravel\Authorization\Events\Role\ExclusionDeclared;
use SineMacula\Laravel\Authorization\Events\Role\ExclusionRemoved;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpired as RolePermissionExpired;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpiryChanged as RolePermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted as RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked as RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Role\Updated as RoleUpdated;
use SineMacula\Laravel\Authorization\Events\SystemOverrideUsed;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthorizationEventMapper;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Authorization\RekeyedTenancy;
use Tests\Fixtures\Models\Person;

/**
 * Unit tests for the mapper of laravel-authorization's events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationEventMapper::class)]
#[CoversClass(TenantTranslator::class)]
#[CoversClass(TenantReferences::class)]
final class AuthorizationEventMapperTest extends TestCase
{
    /** @var string The operation every change is part of. */
    private const string OPERATION = '0196f5d4-4d8b-7c3e-9b1a-1f2e3d4c5b6a';

    /** @var string The tenant every scoped change and decision is in. */
    private const string TENANT = 'org-1';

    /**
     * Forget any morph map a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * Every code is provided for.
     *
     * @return void
     */
    public function testEveryCodeIsProvidedFor(): void
    {
        $provided = array_map(static fn (array $row): string => $row[1]->value, iterator_to_array(self::provideEvents(), false));
        $codes    = array_map(static fn (AuthorizationActivity $code): string => $code->value, AuthorizationActivity::cases());

        self::assertEqualsCanonicalizing($codes, array_values(array_unique($provided)));
    }

    /**
     * Rows of `[event, code, properties]` for every event recorded.
     *
     * @return iterable<string, array{0: object, 1: \SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity, 2: array<string, mixed>}>
     */
    public static function provideEvents(): iterable
    {
        $operation = self::operation();
        $role      = new Reference('role', '3');
        $grant     = new Reference('permission', '4');
        $policy    = new Reference('policy', '5');
        $grantee   = self::person('7');
        $scope     = new GrantScope(new Reference('organisation', self::TENANT), 'admin', false);
        $tenant    = new GrantScope(new Reference('organisation', self::TENANT));
        $where     = ['application' => 'admin', 'include_subtree' => false];
        $at        = CarbonImmutable::parse('2026-11-09 12:00:00');
        $stamp     = '2026-11-09T12:00:00+00:00';
        $digest    = new DocumentDigest(1, str_repeat('a', 64));
        $document  = ['name' => 'Reviewers', 'document_version' => 1, 'document_digest' => str_repeat('a', 64)];
        $changes   = ['before' => ['name' => 'Old', 'description' => 'x'], 'after' => ['name' => 'New']];
        $call      = ['trusted' => false];

        yield 'a denial' => [
            self::decision(DecisionEffect::DENY, DecisionReason::TENANT_SCOPE),
            AuthorizationActivity::ACCESS_DENIED,
            ['action' => 'invoices:refund', 'resource' => 'invoice:9', 'application' => 'admin', 'policies' => ['Billing[12]#0']],
        ];

        yield 'a sensitive action allowed' => [
            self::decision(DecisionEffect::ALLOW, null, report: DecisionReport::SENSITIVE_ACTION),
            AuthorizationActivity::ACCESS_ALLOWED,
            ['action' => 'invoices:refund', 'resource' => 'invoice:9', 'application' => 'admin', 'policies' => ['Billing[12]#0']],
        ];

        yield 'a break-glass grant used' => [
            self::decision(DecisionEffect::ALLOW, null, breakGlass: true),
            AuthorizationActivity::BREAK_GLASS_USED,
            ['action' => 'invoices:refund', 'resource' => 'invoice:9', 'application' => 'admin', 'policies' => ['Billing[12]#0'], 'activations' => ['activation-1']],
        ];

        yield 'a preview' => [
            self::decision(DecisionEffect::DENY, DecisionReason::NO_MATCH, self::person('1')),
            AuthorizationActivity::ACCESS_PREVIEWED,
            ['action' => 'invoices:refund', 'resource' => 'invoice:9', 'application' => 'admin', 'policies' => ['Billing[12]#0'], 'effect' => 'deny', 'reason' => 'no_match'],
        ];

        yield 'a role created' => [
            new RoleCreated($operation, $role, 'Billing', 'api', null, true),
            AuthorizationActivity::ROLE_CREATED,
            [...$call, 'name' => 'Billing', 'guard' => 'api', 'system' => true],
        ];

        yield 'a role updated' => [
            new RoleUpdated($operation, $role, 'New', null, null, $changes),
            AuthorizationActivity::ROLE_UPDATED,
            [...$call, 'name' => 'New', 'changes' => ['description', 'name']],
        ];

        yield 'a role deleted' => [
            new RoleDeleted($operation, $role, 'Billing', null, null, [], [$grant]),
            AuthorizationActivity::ROLE_DELETED,
            [...$call, 'name' => 'Billing', 'grantee_count' => 0, 'permission_count' => 1],
        ];

        yield 'a role exclusion declared' => [
            new ExclusionDeclared($operation, $role, 'Billing', new Reference('role', '6'), 'Approvals', null),
            AuthorizationActivity::ROLE_EXCLUSION_DECLARED,
            [...$call, 'role_name' => 'Billing', 'excluded_role' => 'role:6', 'excluded_role_name' => 'Approvals'],
        ];

        yield 'a role exclusion removed' => [
            new ExclusionRemoved($operation, $role, 'Billing', new Reference('role', '6'), 'Approvals', null),
            AuthorizationActivity::ROLE_EXCLUSION_REMOVED,
            [...$call, 'role_name' => 'Billing', 'excluded_role' => 'role:6', 'excluded_role_name' => 'Approvals'],
        ];

        yield 'a permission created' => [
            new PermissionCreated($operation, $grant, 'invoices:refund', null, null, false),
            AuthorizationActivity::PERMISSION_CREATED,
            [...$call, 'name' => 'invoices:refund', 'system' => false],
        ];

        yield 'a permission updated' => [
            new PermissionUpdated($operation, $grant, 'invoices:refund', null, null, $changes),
            AuthorizationActivity::PERMISSION_UPDATED,
            [...$call, 'name' => 'invoices:refund', 'changes' => ['description', 'name']],
        ];

        yield 'a permission deleted' => [
            new PermissionDeleted($operation, $grant, 'invoices:refund', null, null, [], []),
            AuthorizationActivity::PERMISSION_DELETED,
            [...$call, 'name' => 'invoices:refund', 'grantee_count' => 0, 'role_count' => 0],
        ];

        yield 'a policy created' => [
            new PolicyCreated($operation, $policy, 'Reviewers', null, $digest, false),
            AuthorizationActivity::POLICY_CREATED,
            [...$call, ...$document, 'system' => false],
        ];

        yield 'a policy updated' => [
            new PolicyUpdated($operation, $policy, 'Reviewers', null, $changes, $digest, new DocumentDigest(1, str_repeat('b', 64))),
            AuthorizationActivity::POLICY_UPDATED,
            [...$call, ...$document, 'changes' => ['description', 'name'], 'previous_document_digest' => str_repeat('b', 64)],
        ];

        yield 'a policy deleted' => [
            new PolicyDeleted($operation, $policy, 'Reviewers', null, $digest, []),
            AuthorizationActivity::POLICY_DELETED,
            [...$call, ...$document, 'grantee_count' => 0],
        ];

        yield 'a permission granted to a role' => [
            new RolePermissionGranted($operation, $role, 'Billing', $grant, 'invoices:refund', null, $at),
            AuthorizationActivity::PERMISSION_GRANTED,
            [...$call, 'role_name' => 'Billing', 'permission_name' => 'invoices:refund', 'expires_at' => $stamp],
        ];

        yield 'a permission revoked from a role' => [
            new RolePermissionRevoked($operation, $role, 'Billing', $grant, 'invoices:refund', null),
            AuthorizationActivity::PERMISSION_REVOKED,
            [...$call, 'role_name' => 'Billing', 'permission_name' => 'invoices:refund'],
        ];

        yield 'a role\'s permission expired' => [
            new RolePermissionExpired($operation, $role, 'Billing', $grant, 'invoices:refund', null, $at),
            AuthorizationActivity::GRANT_EXPIRED,
            [...$call, 'role_name' => 'Billing', 'permission_name' => 'invoices:refund', 'grant' => 'role_permission', 'expired_at' => $stamp],
        ];

        yield 'a role\'s permission\'s expiry changed' => [
            new RolePermissionExpiryChanged($operation, $role, 'Billing', $grant, 'invoices:refund', null, null, $at),
            AuthorizationActivity::GRANT_EXPIRY_CHANGED,
            [...$call, 'role_name' => 'Billing', 'permission_name' => 'invoices:refund', 'grant' => 'role_permission', 'expires_at' => $stamp],
        ];

        yield 'a role assigned' => [
            new RoleAssigned($operation, $grantee, $role, 'Billing', $scope, $at),
            AuthorizationActivity::ROLE_ASSIGNED,
            [...$call, ...$where, 'name' => 'Billing', 'expires_at' => $stamp],
        ];

        yield 'a role unassigned' => [
            new RoleRevoked($operation, $grantee, $role, 'Billing', $scope),
            AuthorizationActivity::ROLE_UNASSIGNED,
            [...$call, ...$where, 'name' => 'Billing'],
        ];

        yield 'a role expired' => [
            new RoleExpired($operation, $grantee, $role, 'Billing', $scope, $at),
            AuthorizationActivity::GRANT_EXPIRED,
            [...$call, ...$where, 'name' => 'Billing', 'grant' => 'role', 'expired_at' => $stamp],
        ];

        yield 'a role\'s expiry changed' => [
            new RoleExpiryChanged($operation, $grantee, $role, 'Billing', $scope, $at, null),
            AuthorizationActivity::GRANT_EXPIRY_CHANGED,
            [...$call, ...$where, 'name' => 'Billing', 'grant' => 'role', 'previous_expires_at' => $stamp],
        ];

        yield 'a permission assigned' => [
            new PermissionGranted($operation, $grantee, $grant, 'invoices:refund', $scope, null),
            AuthorizationActivity::PERMISSION_ASSIGNED,
            [...$call, ...$where, 'name' => 'invoices:refund'],
        ];

        yield 'a permission unassigned' => [
            new PermissionRevoked($operation, $grantee, $grant, 'invoices:refund', $scope),
            AuthorizationActivity::PERMISSION_UNASSIGNED,
            [...$call, ...$where, 'name' => 'invoices:refund'],
        ];

        yield 'a permission expired' => [
            new PermissionExpired($operation, $grantee, $grant, 'invoices:refund', $scope, $at),
            AuthorizationActivity::GRANT_EXPIRED,
            [...$call, ...$where, 'name' => 'invoices:refund', 'grant' => 'permission', 'expired_at' => $stamp],
        ];

        yield 'a permission\'s expiry changed' => [
            new PermissionExpiryChanged($operation, $grantee, $grant, 'invoices:refund', $scope, null, $at),
            AuthorizationActivity::GRANT_EXPIRY_CHANGED,
            [...$call, ...$where, 'name' => 'invoices:refund', 'grant' => 'permission', 'expires_at' => $stamp],
        ];

        yield 'a policy attached' => [
            new PolicyAttached($operation, $grantee, $policy, 'Reviewers', $scope, $at),
            AuthorizationActivity::POLICY_ATTACHED,
            [...$call, ...$where, 'name' => 'Reviewers', 'expires_at' => $stamp],
        ];

        yield 'a policy detached' => [
            new PolicyDetached($operation, $grantee, $policy, 'Reviewers', $scope),
            AuthorizationActivity::POLICY_DETACHED,
            [...$call, ...$where, 'name' => 'Reviewers'],
        ];

        yield 'a policy expired' => [
            new PolicyExpired($operation, $grantee, $policy, 'Reviewers', $scope, $at),
            AuthorizationActivity::GRANT_EXPIRED,
            [...$call, ...$where, 'name' => 'Reviewers', 'grant' => 'policy', 'expired_at' => $stamp],
        ];

        yield 'a policy\'s expiry changed' => [
            new PolicyExpiryChanged($operation, $grantee, $policy, 'Reviewers', $scope, $at, $at),
            AuthorizationActivity::GRANT_EXPIRY_CHANGED,
            [...$call, ...$where, 'name' => 'Reviewers', 'grant' => 'policy', 'previous_expires_at' => $stamp, 'expires_at' => $stamp],
        ];

        yield 'a boundary set' => [
            new BoundarySet($operation, $grantee, $policy, 'Reviewers', $scope, new Reference('policy', '2')),
            AuthorizationActivity::BOUNDARY_SET,
            [...$call, ...$where, 'name' => 'Reviewers', 'previous_policy' => 'policy:2'],
        ];

        yield 'a boundary removed' => [
            new BoundaryRemoved($operation, $grantee, $policy, 'Reviewers', $scope),
            AuthorizationActivity::BOUNDARY_REMOVED,
            [...$call, ...$where, 'name' => 'Reviewers'],
        ];

        yield 'a guardrail set' => [
            new GuardrailSet($operation, $policy, 'Reviewers', $tenant),
            AuthorizationActivity::GUARDRAIL_SET,
            [...$call, 'include_subtree' => true, 'name' => 'Reviewers'],
        ];

        yield 'a guardrail removed' => [
            new GuardrailRemoved($operation, $policy, 'Reviewers', $tenant),
            AuthorizationActivity::GUARDRAIL_REMOVED,
            [...$call, 'include_subtree' => true, 'name' => 'Reviewers'],
        ];

        yield 'a resource policy attached' => [
            new ResourcePolicyAttached($operation, Person::class, '9', $policy, 'Reviewers', $scope),
            AuthorizationActivity::RESOURCE_POLICY_ATTACHED,
            [...$call, ...$where, 'name' => 'Reviewers', 'resource_type' => Person::class, 'resource_id' => '9'],
        ];

        yield 'a resource policy detached from a type' => [
            new ResourcePolicyDetached($operation, Person::class, null, $policy, 'Reviewers', $scope),
            AuthorizationActivity::RESOURCE_POLICY_DETACHED,
            [...$call, ...$where, 'name' => 'Reviewers', 'resource_type' => Person::class],
        ];

        yield 'a system override used' => [
            new SystemOverrideUsed($operation, $role, 'Administrator', null, 'rename'),
            AuthorizationActivity::SYSTEM_OVERRIDE_USED,
            [...$call, 'name' => 'Administrator', 'protected_operation' => 'rename'],
        ];
    }

    /**
     * Each event is recorded under its code, keeping what its code keeps.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity  $code
     * @param  array<string, mixed>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEachEventIsRecordedUnderItsCode(object $event, AuthorizationActivity $code, array $properties): void
    {
        $snapshot = self::snapshotOf($event);

        self::assertSame($code->value, $snapshot->code?->value);
        $recorded = $snapshot->properties ?? [];

        ksort($properties);
        ksort($recorded);

        self::assertSame($properties, $recorded);
    }

    /**
     * Rows of `[event]` the mapper skips.
     *
     * @return iterable<string, array{0: object}>
     */
    public static function provideSkipped(): iterable
    {
        yield 'an allow' => [self::decision(DecisionEffect::ALLOW, null)];

        yield 'an allow reported because every allow is' => [self::decision(DecisionEffect::ALLOW, null, report: DecisionReport::ALL_ALLOWS)];

        yield 'a hard denial, already recorded' => [
            new AuthorizationFailed(null, null, null, 'invoices:refund', null, null, null, DecisionEffect::DENY, DecisionReason::NO_MATCH, [], false, [], []),
        ];

        yield 'another of its events' => [new class implements AuthorizationEvent {}];

        yield 'a change with no code' => [\Mockery::mock(AuthorizationMutation::class, ['operation' => 'role.archived'])];

        yield 'another member\'s event' => [new \stdClass];
    }

    /**
     * Each skipped event records nothing.
     *
     * @param  object  $event
     * @return void
     */
    #[DataProvider('provideSkipped')]
    public function testEachSkippedEventRecordsNothing(object $event): void
    {
        self::assertNull(self::mapper()->map($event, new PendingRecord));
    }

    /**
     * A denial is the identity's, denied with its reason.
     *
     * @return void
     */
    public function testADenialIsTheSubjectsAndDeniedWithItsReason(): void
    {
        $record   = new PendingRecord;
        $snapshot = self::mapper()->map(self::decision(DecisionEffect::DENY, DecisionReason::ADMINISTRATION_SCOPE), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertSame([Outcome::DENIED, 'administration.scope'], [$snapshot->outcome, $snapshot->reason]);
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->actor?->toArray());
        self::assertSame(['type' => 'member', 'id' => '70'], $snapshot->principal?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => self::TENANT], $snapshot->tenant?->toArray());
        self::assertNull($snapshot->correlationId);
    }

    /**
     * A denial for want of a stronger proof is recorded.
     *
     * @return void
     */
    public function testADenialForWantOfAStrongerProofIsRecorded(): void
    {
        $record   = new PendingRecord;
        $snapshot = self::mapper()->map(self::decision(DecisionEffect::DENY, DecisionReason::INSUFFICIENT_AUTHENTICATION), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertSame(AuthorizationActivity::ACCESS_DENIED->value, $snapshot->code?->value);
        self::assertSame([Outcome::DENIED, 'insufficient_authentication'], [$snapshot->outcome, $snapshot->reason]);
    }

    /**
     * A denial that names no reason is still recorded as denied, with none.
     *
     * @return void
     */
    public function testADenialWithNoReasonIsDeniedWithNone(): void
    {
        $snapshot = self::mapper()->map(self::decision(DecisionEffect::DENY, null), new PendingRecord)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertSame([Outcome::DENIED, null], [$snapshot->outcome, $snapshot->reason]);
    }

    /**
     * A guest's denial names no one and no tenant.
     *
     * @return void
     */
    public function testAGuestsDenialNamesNoOne(): void
    {
        $record   = new PendingRecord;
        $event    = new DecisionEvaluated(null, null, null, 'invoices:view', null, null, null, DecisionEffect::DENY, DecisionReason::SUBJECT_UNRESOLVED, [], false, [], []);
        $snapshot = self::mapper()->map($event, $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertNull($snapshot->actor);
        self::assertNull($snapshot->principal);
        self::assertNull($snapshot->subject);
        self::assertNull($snapshot->tenant);
        self::assertSame(['action' => 'invoices:view', 'policies' => []], $snapshot->properties);
        self::assertSame([Outcome::DENIED, 'subject_unresolved'], [$snapshot->outcome, $snapshot->reason]);
    }

    /**
     * A principal with no identity is both actor and principal.
     *
     * @return void
     */
    public function testAPrincipalWithNoIdentityIsTheActor(): void
    {
        $machine  = new Reference('machine', '3');
        $event    = new DecisionEvaluated($machine, null, null, 'invoices:view', null, null, null, DecisionEffect::DENY, DecisionReason::NO_MATCH, [], false, [], []);
        $snapshot = self::snapshotOf($event);

        self::assertSame(['type' => 'machine', 'id' => '3'], $snapshot->actor?->toArray());
        self::assertSame(['type' => 'machine', 'id' => '3'], $snapshot->principal?->toArray());
        self::assertSame(['type' => 'machine', 'id' => '3'], $snapshot->subject?->toArray());
    }

    /**
     * A preview is the previewer's, about the principal previewed.
     *
     * @return void
     */
    public function testAPreviewIsThePreviewersAboutThePrincipalPreviewed(): void
    {
        $record   = new PendingRecord;
        $snapshot = self::mapper()->map(self::decision(DecisionEffect::ALLOW, null, self::person('1')), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertSame(AuthorizationActivity::ACCESS_PREVIEWED->value, $snapshot->code?->value);
        self::assertSame(['type' => Person::class, 'id' => '1'], $snapshot->actor?->toArray());
        self::assertSame(['type' => 'member', 'id' => '70'], $snapshot->subject?->toArray());
        self::assertNull($snapshot->principal);
        self::assertSame([Outcome::SUCCESS, null], [$snapshot->outcome, $snapshot->reason]);
        self::assertSame('allow', $snapshot->properties['effect'] ?? null);
    }

    /**
     * A preview naming no principal is about the identity previewed.
     *
     * @return void
     */
    public function testAPreviewNamingNoPrincipalIsAboutTheIdentity(): void
    {
        $reason   = DecisionReason::NO_MATCH;
        $event    = new DecisionEvaluated(null, self::person('7'), self::person('1'), 'invoices:view', null, null, null, DecisionEffect::DENY, $reason, [], false, [], []);
        $snapshot = self::snapshotOf($event);

        self::assertSame(AuthorizationActivity::ACCESS_PREVIEWED->value, $snapshot->code?->value);
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
    }

    /**
     * A check a break-glass grant allowed succeeds.
     *
     * @return void
     */
    public function testABreakGlassGrantUsedSucceeds(): void
    {
        $snapshot = self::snapshotOf(self::decision(DecisionEffect::ALLOW, null, breakGlass: true));

        self::assertSame([Outcome::SUCCESS, null], [$snapshot->outcome, $snapshot->reason]);
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->actor?->toArray());
    }

    /**
     * A sensitive action's allow succeeds.
     *
     * @return void
     */
    public function testASensitiveActionAllowedSucceeds(): void
    {
        $snapshot = self::snapshotOf(self::decision(DecisionEffect::ALLOW, null, report: DecisionReport::SENSITIVE_ACTION));

        self::assertSame([Outcome::SUCCESS, null], [$snapshot->outcome, $snapshot->reason]);
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->actor?->toArray());
    }

    /**
     * Only a decision waits for its transaction to end.
     *
     * @return void
     */
    public function testOnlyADecisionWaitsForItsTransactionToEnd(): void
    {
        $change = new RoleAssigned(self::operation(), self::person('9'), new Reference('role', '3'), 'Billing', new GrantScope(new Reference('organisation', self::TENANT)), null);

        self::assertSame(Timing::AFTER_TRANSACTION, self::snapshotOf(self::decision(DecisionEffect::DENY, null))->timing);
        self::assertNull(self::snapshotOf($change)->timing);
    }

    /**
     * A delegated change is the caller's, correlated by its operation.
     *
     * @return void
     */
    public function testADelegatedChangeIsTheCallersAndCorrelatedByItsOperation(): void
    {
        $record   = new PendingRecord;
        $scope    = new GrantScope(new Reference('organisation', self::TENANT));
        $event    = new RoleAssigned(self::operation(), self::person('9'), new Reference('role', '3'), 'Billing', $scope, null);
        $snapshot = self::mapper()->map($event, $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->actor?->toArray());
        self::assertSame(['type' => 'member', 'id' => '70'], $snapshot->principal?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '9'], $snapshot->subject?->toArray());
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => self::TENANT], $snapshot->tenant?->toArray());
        self::assertSame('authorization:' . self::OPERATION, $snapshot->correlationId);
        self::assertSame(Outcome::SUCCESS, $snapshot->outcome);
        self::assertNull($snapshot->manifest);
    }

    /**
     * Trusted and system changes name only what the call named.
     *
     * @return void
     */
    public function testTrustedAndSystemChangesNameOnlyWhatTheCallNamed(): void
    {
        $role     = new Reference('role', '3');
        $command  = self::snapshotOf(new RoleCreated(new Operation(self::OPERATION, new Reference('operator', '2'), CarbonImmutable::now()), $role, 'Billing', null, null, false));
        $system   = new PendingRecord;
        $sweep    = new Operation(self::OPERATION, null, CarbonImmutable::now());
        $expired  = new RoleExpired($sweep, self::person('9'), $role, 'Billing', GrantScope::platform(), CarbonImmutable::now());
        $snapshot = self::mapper()->map($expired, $system)?->snapshot();

        self::assertSame(['type' => 'operator', 'id' => '2'], $command->actor?->toArray());
        self::assertNull($command->principal);
        self::assertTrue($command->properties['trusted'] ?? null);
        self::assertSame(['type' => 'role', 'id' => '3'], $command->subject?->toArray());
        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($system->isActorSettled());
        self::assertNull($snapshot->actor);
        self::assertNull($snapshot->tenant);
    }

    /**
     * A guardrail is about its tenant, a policy on a whole resource type none.
     *
     * @return void
     */
    public function testAGuardrailIsAboutItsTenant(): void
    {
        $scope     = new GrantScope(new Reference('organisation', self::TENANT));
        $policy    = new Reference('policy', '5');
        $guardrail = self::snapshotOf(new GuardrailSet(self::operation(), $policy, 'Reviewers', $scope));
        $type      = self::snapshotOf(new ResourcePolicyAttached(self::operation(), Person::class, null, $policy, 'Reviewers', $scope));

        self::assertSame(['type' => 'organisation', 'id' => self::TENANT], $guardrail->subject?->toArray());
        self::assertNull($type->subject);
    }

    /**
     * A role exclusion is the caller's, about the pair's first role.
     *
     * @return void
     */
    public function testARoleExclusionIsAboutItsFirstRoleInItsTenant(): void
    {
        $tenant  = new Reference('organisation', self::TENANT);
        $role    = new Reference('role', '3');
        $other   = new Reference('role', '6');
        $changes = [
            self::snapshotOf(new ExclusionDeclared(self::operation(), $role, 'Billing', $other, 'Approvals', $tenant)),
            self::snapshotOf(new ExclusionRemoved(self::operation(), $role, 'Billing', $other, 'Approvals', $tenant)),
        ];

        foreach ($changes as $snapshot) {
            self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->actor?->toArray());
            self::assertSame(['type' => 'role', 'id' => '3'], $snapshot->subject?->toArray());
            self::assertSame(['type' => References::TENANT_TYPE, 'id' => self::TENANT], $snapshot->tenant?->toArray());
            self::assertSame('authorization:' . self::OPERATION, $snapshot->correlationId);
            self::assertNull($snapshot->manifest);
        }
    }

    /**
     * A system override is the caller's, about the record, in its tenant.
     *
     * @return void
     */
    public function testASystemOverrideIsTheCallersAboutTheRecord(): void
    {
        $tenant   = new Reference('organisation', self::TENANT);
        $record   = new PendingRecord;
        $snapshot = self::mapper()->map(new SystemOverrideUsed(self::operation(), new Reference('role', '3'), 'Administrator', $tenant, 'delete'), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->actor?->toArray());
        self::assertSame(['type' => 'member', 'id' => '70'], $snapshot->principal?->toArray());
        self::assertSame(['type' => 'role', 'id' => '3'], $snapshot->subject?->toArray());
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => self::TENANT], $snapshot->tenant?->toArray());
        self::assertSame('authorization:' . self::OPERATION, $snapshot->correlationId);
    }

    /**
     * References are read through the morph map, the tenant by its key.
     *
     * @return void
     */
    public function testReferencesAreReadThroughTheMorphMap(): void
    {
        Relation::morphMap(['person' => Person::class]);

        $scope    = new GrantScope(new Reference('organisation', '12'));
        $event    = new ResourcePolicyAttached(self::operation(), Person::class, '9', new Reference('policy', '5'), 'Reviewers', $scope);
        $snapshot = self::snapshotOf($event);

        self::assertSame(['type' => 'person', 'id' => '7'], $snapshot->actor?->toArray());
        self::assertSame(['type' => 'person', 'id' => '9'], $snapshot->subject?->toArray());
        self::assertSame('person', $snapshot->properties['resource_type'] ?? null);
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => '12'], $snapshot->tenant?->toArray());
    }

    /**
     * A tenant not keyed by its identifier is recorded with no tenant.
     *
     * @return void
     */
    public function testATenantNotKeyedByItsIdentifierIsRecordedWithNoTenant(): void
    {
        $mapper   = self::mapper(tenancy: new RekeyedTenancy(['7' => '3', '12' => '7']));
        $tenant   = new Reference(Organisation::TYPE, '7');
        $scope    = new GrantScope($tenant);
        $member   = new Reference('member', '70');
        $decision = new DecisionEvaluated($member, self::person('7'), null, 'invoices:refund', 'invoice:9', $tenant, 'admin', DecisionEffect::DENY, null, [], false, [], []);
        $change   = new ResourcePolicyAttached(self::operation(), Person::class, '9', new Reference('policy', '5'), 'Reviewers', $scope);

        self::assertNull($mapper->map($decision, new PendingRecord)?->snapshot()->tenant);
        self::assertNull($mapper->map($change, new PendingRecord)?->snapshot()->tenant);
    }

    /**
     * A tenant of another type is recorded with no tenant.
     *
     * @return void
     */
    public function testATenantOfAnotherTypeIsRecordedWithNoTenant(): void
    {
        $scope  = new GrantScope(new Reference('another-type', self::TENANT));
        $change = new ResourcePolicyAttached(self::operation(), Person::class, '9', new Reference('policy', '5'), 'Reviewers', $scope);

        self::assertNull(self::snapshotOf($change)->tenant);
    }

    /**
     * Rows of `[deletion]` that took a grant from two grantees.
     *
     * @return iterable<string, array{0: object}>
     */
    public static function provideDeletions(): iterable
    {
        $operation = self::operation();
        $grantees  = [self::person('8'), self::person('9'), self::person('8'), self::person('')];

        yield 'a role' => [new RoleDeleted($operation, new Reference('role', '3'), 'Billing', null, null, $grantees, [])];

        yield 'a permission' => [new PermissionDeleted($operation, new Reference('permission', '4'), 'invoices:refund', null, null, $grantees, [])];

        yield 'a policy' => [new PolicyDeleted($operation, new Reference('policy', '5'), 'Reviewers', null, new DocumentDigest(1, str_repeat('a', 64)), $grantees)];
    }

    /**
     * A deletion covers each grantee it took a grant from, once.
     *
     * @param  object  $event
     * @return void
     */
    #[DataProvider('provideDeletions')]
    public function testADeletionCarriesItsGranteesAsItsManifest(object $event): void
    {
        $container = new Container;

        $container->instance(AuditStore::class, new NullAuditStore);

        $snapshot = self::mapper($container)->map($event, self::captured($container))?->snapshot();

        self::assertSame(2, $snapshot?->manifest?->count);
        self::assertSame(json_encode([[Person::class, '8'], [Person::class, '9']]), $snapshot->manifest->canonical);
        self::assertSame(4, $snapshot->properties['grantee_count'] ?? null);
    }

    /**
     * A permission deletion covers the roles that held it beside its grantees.
     *
     * @return void
     */
    public function testAPermissionDeletionCoversItsRoles(): void
    {
        $container = new Container;

        $container->instance(AuditStore::class, new NullAuditStore);

        $event    = new PermissionDeleted(self::operation(), new Reference('permission', '4'), 'invoices:refund', null, null, [self::person('8')], [new Reference('role', '3')]);
        $snapshot = self::mapper($container)->map($event, self::captured($container))?->snapshot();

        self::assertSame(json_encode([[Person::class, '8'], ['role', '3']]), $snapshot?->manifest?->canonical);
        self::assertSame(1, $snapshot->properties['role_count'] ?? null);
    }

    /**
     * A change about nothing covers every grantee it altered.
     *
     * @return void
     */
    public function testAChangeAboutNothingCoversEveryGrantee(): void
    {
        $container = new Container;

        $container->instance(AuditStore::class, new NullAuditStore);

        $event = \Mockery::mock(AuthorizationMutation::class, [
            'operation'       => 'role.deleted',
            'operationId'     => self::OPERATION,
            'isTrusted'       => true,
            'actor'           => null,
            'actorIdentity'   => null,
            'subject'         => null,
            'tenant'          => null,
            'application'     => null,
            'grantees'        => [self::person('8')],
            'auditProperties' => [],
        ]);

        $snapshot = self::mapper($container)->map($event, self::captured($container))?->snapshot();

        self::assertNull($snapshot?->subject);
        self::assertSame(json_encode([[Person::class, '8']]), $snapshot?->manifest?->canonical);
    }

    /**
     * A deletion is refused where the store keeps no attachment.
     *
     * @return void
     */
    public function testADeletionIsRefusedWhereTheStoreKeepsNoAttachment(): void
    {
        $container = new Container;

        $container->instance(AuditStore::class, \Mockery::mock(AuditStore::class));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('does not keep attachments');

        self::mapper($container)->map(iterator_to_array(self::provideDeletions())['a role'][0], self::captured($container));
    }

    /**
     * A builder as audit-log's capture hands a mapper one.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function captured(Container $container): PendingRecord
    {
        $manifests = new BulkManifests(new StoreCapabilities($container), new CaptureSettings(new Repository([])));

        return new PendingRecord(manifests: $manifests->of(...));
    }

    /**
     * The mapper, resolving every organisation unless told otherwise.
     *
     * @param  ?\Illuminate\Container\Container  $container
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\TenantResolver  $tenancy
     * @return \SineMacula\Laravel\Iam\Audit\Mappers\AuthorizationEventMapper
     */
    private static function mapper(?Container $container = null, ?TenantResolver $tenancy = null): AuthorizationEventMapper
    {
        $container ??= new Container;

        $container->instance(TenantResolver::class, $tenancy ?? new OrganisationTenancy);

        return new AuthorizationEventMapper(new TenantTranslator(new TenantReferences($container)));
    }

    /**
     * The snapshot of the record the mapper describes for the event.
     *
     * @param  object  $event
     * @return \SineMacula\Laravel\AuditLog\Records\PendingSnapshot
     */
    private static function snapshotOf(object $event): PendingSnapshot
    {
        $record = self::mapper()->map($event, new PendingRecord);

        self::assertInstanceOf(PendingRecord::class, $record);

        return $record->snapshot();
    }

    /**
     * A decision about the person's principal, in the tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect  $effect
     * @param  ?\SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @param  ?\SineMacula\Laravel\Authorization\Support\Reference  $previewer
     * @param  bool  $breakGlass
     * @param  ?\SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport  $report
     * @return \SineMacula\Laravel\Authorization\Events\DecisionEvaluated
     */
    private static function decision(
        DecisionEffect $effect,
        ?DecisionReason $reason,
        ?Reference $previewer = null,
        bool $breakGlass = false,
        ?DecisionReport $report = null,
    ): DecisionEvaluated {
        return new DecisionEvaluated(
            new Reference('member', '70'),
            self::person('7'),
            $previewer,
            'invoices:refund',
            'invoice:9',
            new Reference('organisation', self::TENANT),
            'admin',
            $effect,
            $reason,
            [new StatementReference('Billing', 0, '12')],
            $breakGlass,
            $breakGlass ? ['activation-1'] : [],
            ['subject.id'],
            $report,
        );
    }

    /**
     * A delegated call, by the member acting for the person.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Operation
     */
    private static function operation(): Operation
    {
        return new Operation(self::OPERATION, new Reference('member', '70'), CarbonImmutable::now(), false, self::person('7'));
    }

    /**
     * A reference to a person.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function person(string $id): Reference
    {
        return new Reference(Person::class, $id);
    }
}
