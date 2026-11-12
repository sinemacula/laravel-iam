<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Records\Reference as AuditReference;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Testing\FakeTenantTree;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Iam\Authorization\AuditAccessPolicyAdapter;
use SineMacula\Laravel\Iam\Authorization\PermissionCatalogue;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use Tests\Concerns\MigratesAuthorization;
use Tests\Fixtures\Authorization\GrantedSeat;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Authorization\RecordingGrantHook;
use Tests\Fixtures\Authorization\Staff;
use Tests\Fixtures\Authorization\UnscopedTenancy;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditAccessPolicyAdapter::class)]
final class AuditAccessPolicyAdapterTest extends TestCase
{
    use MigratesAuthorization;

    /** @var string A tenant. */
    private const string FIRST = 'org-1';

    /** @var string Another tenant. */
    private const string SECOND = 'org-2';

    /** @var string A third tenant. */
    private const string THIRD = 'org-3';

    /** @var \SineMacula\Laravel\Iam\Testing\FakeMemberships The viewers' memberships. */
    private FakeMemberships $memberships;

    /**
     * Store the catalogue's permissions, resolve the organisations and fake the
     * memberships.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        foreach ((new PermissionCatalogue)->permissions() as $definition) {
            Permission::query()->create(['name' => $definition->name]);
        }

        $this->app?->instance(GrantHook::class, new RecordingGrantHook);
        $this->app?->singleton(TenantResolver::class, OrganisationTenancy::class);

        $this->memberships = FakeMemberships::fake($this->app);
    }

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
     * A tenant grant is seen in its tenant, a member of it or not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantGrantIsSeenInItsTenant(): void
    {
        $viewer = $this->viewer();

        self::assertTrue(self::scope($viewer)->isDenied());

        $this->grant($viewer, 'audit-log.read', self::FIRST);
        $this->grant($viewer, 'audit-log.read', self::SECOND);
        $this->member($viewer, self::THIRD);

        $scope = self::scope($viewer);

        self::assertSame([self::tenant(self::FIRST), self::tenant(self::SECOND)], self::tenants($scope));
        self::assertNull($scope->categories());
        self::assertFalse($scope->includesTenantless());
    }

    /**
     * A platform-wide grant is seen in the viewer's tenants whose own decision
     * allows its purpose.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformGrantIsSeenInTheViewersTenantsThatAllowIt(): void
    {
        $alone  = $this->viewer('audit-log.read');
        $viewer = $this->viewer('audit-log.read', 'audit-log.count');

        $viewer->attachPolicy(self::policy('deny', false), tenant: new Reference(Organisation::TYPE, self::SECOND), includeSubtree: false);

        $this->grant($alone, 'audit-log.read', self::THIRD);
        $this->memberships->grant($viewer, Membership::platform());
        $this->member($viewer, self::FIRST, self::SECOND);

        self::assertSame([self::tenant(self::THIRD)], self::tenants(self::scope($alone)));
        self::assertSame([self::tenant(self::FIRST)], self::tenants(self::scope($viewer)));
        self::assertSame([self::tenant(self::FIRST), self::tenant(self::SECOND)], self::tenants(self::scope($viewer, ReadPurpose::COUNT)));
        self::assertTrue(self::scope($viewer, ReadPurpose::EXPORT)->isDenied());
    }

    /**
     * A subtree grant is seen at its root and in the viewer's tenants below it,
     * never in another tenant below it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubtreeGrantIsSeenInTheViewersTenantsBelowIt(): void
    {
        $first = new Reference(Organisation::TYPE, self::FIRST);

        $this->app?->instance(TenantTree::class, FakeTenantTree::of([
            [$first, null],
            [new Reference(Organisation::TYPE, self::SECOND), $first],
            [new Reference(Organisation::TYPE, self::THIRD), $first],
        ]));

        $subtree = $this->viewer();
        $node    = $this->viewer();

        $subtree->givePermission('audit-log.read', tenant: $first);
        $node->givePermission('audit-log.read', tenant: $first, includeSubtree: false);
        $this->member($subtree, self::SECOND);
        $this->member($node, self::SECOND);

        self::assertSame([self::tenant(self::FIRST), self::tenant(self::SECOND)], self::tenants(self::scope($subtree)));
        self::assertSame([self::tenant(self::FIRST)], self::tenants(self::scope($node)));
    }

    /**
     * The scope is never wider than any tenant's grant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheScopeIsNeverWiderThanAnyTenantsGrant(): void
    {
        $narrowed = $this->viewer();
        $disjoint = $this->viewer();

        $this->grant($narrowed, 'audit-log.read', self::FIRST);
        $this->grant($narrowed, 'audit-log.read.security', self::SECOND);
        $this->grant($narrowed, 'audit-log.read.audit', self::SECOND);
        $this->grant($disjoint, 'audit-log.read.security', self::FIRST);
        $this->grant($disjoint, 'audit-log.read.audit', self::SECOND);

        $scope = self::scope($narrowed);

        self::assertSame([self::tenant(self::FIRST), self::tenant(self::SECOND)], self::tenants($scope));
        self::assertSame(['audit', 'security'], $scope->categories());
        self::assertTrue(self::scope($disjoint)->isDenied());
    }

    /**
     * An own-activity grant sees only the viewer's own activity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOwnActivityGrantSeesOnlyTheViewersOwnActivity(): void
    {
        $viewer = $this->viewer('audit-log.read.own');
        $person = $this->viewer();
        $seat   = GrantedSeat::query()->create(['person_id' => $person->getKey(), 'tenant_id' => self::FIRST]);

        $this->member($viewer, self::FIRST, self::SECOND);
        $seat->givePermission('audit-log.read.own');

        $scope = self::scope($viewer);

        self::assertSame([self::tenant(self::FIRST), self::tenant(self::SECOND)], self::tenants($scope));
        self::assertSame([[References::type(Staff::class), self::keyOf($viewer)]], self::about($scope));

        $this->app?->forgetInstance(FakeMemberships::MEMBERSHIPS);

        $scope = self::scope(AuditReference::to($seat));

        self::assertSame([self::tenant(self::FIRST)], self::tenants($scope));
        self::assertCount(2, self::about($scope));
    }

    /**
     * A permission whose decision reads an authentication requirement is not
     * held.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPermissionWhoseDecisionReadsARequirementIsNotHeld(): void
    {
        $denied  = $this->viewer('audit-log.read');
        $allowed = $this->viewer();
        $beside  = $this->viewer('audit-log.read');

        $denied->attachPolicy(self::policy('deny', true), tenant: new Reference(Organisation::TYPE, self::SECOND), includeSubtree: false);
        $allowed->attachPolicy(self::policy('allow', true));
        $beside->attachPolicy(self::policy('allow', true));

        $this->member($denied, self::FIRST, self::SECOND);
        $this->member($allowed, self::FIRST);
        $this->member($beside, self::FIRST);

        self::assertSame([self::tenant(self::FIRST)], self::tenants(self::scope($denied)));
        self::assertTrue(self::scope($allowed)->isDenied());
        self::assertTrue(self::scope($beside)->isDenied());
    }

    /**
     * A principal's own grants count only where its tenant access lets it act;
     * its identity's count anywhere.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalsGrantsCountOnlyWhereItMayAct(): void
    {
        $person = $this->viewer();
        $seat   = GrantedSeat::query()->create(['person_id' => $person->getKey(), 'tenant_id' => self::FIRST]);

        $seat->givePermission('audit-log.read', tenant: new Reference(Organisation::TYPE, self::FIRST));
        $seat->givePermission('audit-log.read', tenant: new Reference(Organisation::TYPE, self::SECOND));
        $this->grant($person, 'audit-log.read', self::THIRD);

        self::assertSame([self::tenant(self::FIRST), self::tenant(self::THIRD)], self::tenants(self::scope(AuditReference::to($seat))));

        $this->app?->instance(TenantAccess::class, new class implements TenantAccess {
            /**
             * Let the principal act in any tenant.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
             * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
             * @return bool
             */
            #[\Override]
            public function mayActIn(Principal $principal, ?Tenant $tenant): bool
            {
                return true;
            }
        });

        self::assertSame([self::tenant(self::FIRST), self::tenant(self::SECOND), self::tenant(self::THIRD)], self::tenants(self::scope(AuditReference::to($seat))));
    }

    /**
     * A viewer named by a reference is the model it names, one naming nobody is
     * refused, and a viewer that is no model sees nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAViewerIsTheModelItNames(): void
    {
        Relation::morphMap(['staff' => Staff::class]);

        $viewer = $this->viewer();

        $this->grant($viewer, 'audit-log.read', self::FIRST);

        self::assertSame([self::tenant(self::FIRST)], self::tenants(self::scope(AuditReference::of('staff', self::keyOf($viewer)))));
        self::assertTrue(self::scope(new GenericUser(['id' => self::keyOf($viewer)]))->isDenied());

        $this->expectException(UnresolvedReferenceException::class);

        self::scope(AuditReference::of('nothing', '1'));
    }

    /**
     * A tenant the tenant resolver cannot name is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantTheResolverCannotNameIsRefused(): void
    {
        $viewer = $this->viewer();

        $this->grant($viewer, 'audit-log.read', self::FIRST);
        $this->app?->instance(TenantResolver::class, new UnscopedTenancy);

        $this->expectException(UnresolvedReferenceException::class);

        self::scope($viewer);
    }

    /**
     * Name the catalogue among `laravel-authorization`'s permission providers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $app->make('config')->set('authorization.permission_providers', [PermissionCatalogue::class]);
    }

    /**
     * A viewer granted the permissions platform-wide.
     *
     * @param  string  ...$permissions
     * @return \Tests\Fixtures\Authorization\Staff
     */
    private function viewer(string ...$permissions): Staff
    {
        $viewer = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => uniqid('ada', true) . '@example.test']);

        foreach ($permissions as $permission) {
            $viewer->givePermission($permission);
        }

        return $viewer;
    }

    /**
     * Grant the viewer the permission in the tenant.
     *
     * @param  \Tests\Fixtures\Authorization\Staff  $viewer
     * @param  string  $permission
     * @param  string  $tenantId
     * @return void
     */
    private function grant(Staff $viewer, string $permission, string $tenantId): void
    {
        $viewer->givePermission($permission, tenant: new Reference(Organisation::TYPE, $tenantId));
    }

    /**
     * Make the viewer a member of the tenants.
     *
     * @param  \Tests\Fixtures\Authorization\Staff  $viewer
     * @param  string  ...$tenantIds
     * @return void
     */
    private function member(Staff $viewer, string ...$tenantIds): void
    {
        foreach ($tenantIds as $tenantId) {
            $this->memberships->grant($viewer, Membership::of($tenantId));
        }
    }

    /**
     * A policy of one statement on reading the trail, under a multifactor
     * requirement when guarded.
     *
     * @param  string  $effect
     * @param  bool  $guarded
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $effect, bool $guarded): Policy
    {
        $statement = ['sid' => 'trail', 'effect' => $effect, 'actions' => ['audit-log.read']];

        if ($guarded) {
            $statement['conditions'] = ['authentication_requirement' => ['authentication' => ['multifactor' => []]]];
        }

        return Policy::query()->create(['name' => uniqid($effect, true), 'document' => ['statements' => [$statement]]]);
    }

    /**
     * The scope the adapter answers for the viewer.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     *
     * @throws \Throwable
     */
    private static function scope(AuditReference|Authenticatable $viewer, ReadPurpose $purpose = ReadPurpose::READ): AccessScope
    {
        return (new AuditAccessPolicyAdapter)->scope($viewer, $purpose);
    }

    /**
     * The tenant as a scope lists it.
     *
     * @param  string  $tenantId
     * @return array{0: string, 1: string}
     */
    private static function tenant(string $tenantId): array
    {
        return [References::TENANT_TYPE, $tenantId];
    }

    /**
     * The tenants the scope sees.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return list<array{0: string, 1: string}>
     */
    private static function tenants(AccessScope $scope): array
    {
        $tenants = $scope->toArray()['tenants'] ?? null;

        self::assertIsArray($tenants);

        /** @var list<array{0: string, 1: string}> $tenants */
        return $tenants;
    }

    /**
     * The references whose activity the scope sees.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return list<array{0: string, 1: string}>
     */
    private static function about(AccessScope $scope): array
    {
        $about = $scope->toArray()['about'] ?? null;

        self::assertIsArray($about);

        /** @var list<array{0: string, 1: string}> $about */
        return $about;
    }

    /**
     * The model's key, as a string.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    private static function keyOf(Model $model): string
    {
        $key = $model->getKey();

        return is_int($key) || is_string($key) ? (string) $key : self::fail('The model has no key.');
    }
}
