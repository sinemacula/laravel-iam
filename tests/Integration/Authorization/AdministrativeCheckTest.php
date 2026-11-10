<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\AdministrativeCheck;
use SineMacula\Laravel\Iam\Authorization\Enums\AdministrativeOperation;
use SineMacula\Laravel\Iam\Authorization\PermissionCatalogue;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Authorization\RecordingGrantHook;
use Tests\Fixtures\Authorization\Staff;
use Tests\Fixtures\Authorization\UnscopedTenancy;
use Tests\TestCase;

/**
 * Integration tests of the check before a member's administrative operation
 * (IAM-6.9, AUTHZ-14.5): the operation is checked through
 * `laravel-authorization`'s grants for the subject handed in, with the member's
 * object as the resource in its own tenant, so a grant in the object's tenant
 * allows it and a grant in another tenant does not; a denial throws before the
 * operation and is recorded once as `authorization.access_denied`, a refusal
 * for want of a stronger proof on no session among them; and a tenant that
 * resolves to nothing is refused rather than checked as the platform's.
 *
 * Each check reads the grants on the storage connection, so it runs at the
 * connection's own level on every engine, then at READ COMMITTED and REPEATABLE
 * READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdministrativeCheck::class)]
final class AdministrativeCheckTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /** @var string The tenant the administrator acts in. */
    private const string TENANT = 'org-1';

    /** @var string Another tenant. */
    private const string OTHER = 'org-2';

    /**
     * Store the catalogue's permissions, so they can be granted; record grant
     * hooks rather than widen anyone's scope; and resolve the organisations.
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
    }

    /**
     * A grant in the object's tenant allows the operation there, and only
     * there.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAGrantInTheObjectsTenantAllowsTheOperationThere(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $staff = $this->administrator(AdministrativeOperation::SSO_CONNECTION_TRUST->value, new Reference(Organisation::TYPE, self::TENANT));
        $check = $this->check();
        $check->authorize(self::actingIn($staff, self::TENANT), AdministrativeOperation::SSO_CONNECTION_TRUST, 'sso_connection', 'connection-1', self::TENANT);

        $this->expectException(AuthorizationException::class);

        $check->authorize(self::actingIn($staff, self::OTHER), AdministrativeOperation::SSO_CONNECTION_TRUST, 'sso_connection', 'connection-2', self::OTHER);
    }

    /**
     * A denial throws before the operation and is recorded once, as an access
     * denied, with the operation and the object.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADenialThrowsAndIsRecordedOnce(): void
    {
        $fake  = AuditLog::fake();
        $staff = $this->administrator(AdministrativeOperation::MFA_IDENTITY_UNLOCK->value, null);

        try {
            $this->check()->authorize(self::actingIn($staff, self::TENANT), AdministrativeOperation::MFA_IDENTITY_RESET, 'person', '42', self::TENANT);
            self::fail('The reset was allowed.');
        } catch (AuthorizationException) {
            // The denial is what this test checks.
        }

        $records = $fake->recorded(static fn ($record): bool => $record->event === 'authorization.access_denied');

        self::assertCount(1, $records);
        self::assertSame(Outcome::DENIED->value, $records[0]->outcome);
        self::assertSame('mfa.identity.reset', $records[0]->properties['action'] ?? null);
        self::assertSame('person:42', $records[0]->properties['resource'] ?? null);
    }

    /**
     * A subject built for a job or a command carries no session, so an
     * operation its policy allows only after a stronger proof is refused for
     * want of one, which nobody can step up: the refusal is recorded once, as
     * an access denied with its reason, so the trail keeps it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalForWantOfAProofOnNoSessionIsRecorded(): void
    {
        $fake  = AuditLog::fake();
        $staff = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);

        $staff->attachPolicy(Policy::query()->create(['name' => 'resets-after-step-up', 'document' => [
            'statements' => [[
                'sid'        => 'reset-after-step-up',
                'effect'     => 'allow',
                'actions'    => [AdministrativeOperation::MFA_IDENTITY_RESET->value],
                'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => []]]],
            ]],
        ]]));

        try {
            $this->check()->authorize(self::actingIn($staff, self::TENANT), AdministrativeOperation::MFA_IDENTITY_RESET, 'person', '42', self::TENANT);
            self::fail('The reset was allowed without a session.');
        } catch (InsufficientAuthenticationException) {
            // The refusal is what this test checks.
        }

        $records = $fake->recorded(static fn ($record): bool => $record->event === 'authorization.access_denied');

        self::assertCount(1, $records);
        self::assertSame([Outcome::DENIED->value, 'insufficient_authentication'], [$records[0]->outcome, $records[0]->reason]);
        self::assertSame('mfa.identity.reset', $records[0]->properties['action'] ?? null);
    }

    /**
     * An operation on the type alone, named as its name, is checked on the
     * type: a platform-wide grant allows it in any tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperationOnTheTypeIsCheckedOnTheType(): void
    {
        $staff = $this->administrator(AdministrativeOperation::SSO_CONNECTION_CREATE->value, null);

        $this->check()->authorize(self::actingIn($staff, self::TENANT), 'sso.connection.create', 'sso_connection', null, self::TENANT);
        $this->check()->authorize(new Subject($staff, $staff), 'sso.connection.create', 'sso_connection');

        self::assertTrue($staff->hasPermission('sso.connection.create'));
    }

    /**
     * A subject that names no tenant is decided on the platform: a
     * platform-wide grant allows, and a grant in the object's tenant does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubjectWithNoTenantIsDecidedOnThePlatform(): void
    {
        $platform = $this->administrator(AdministrativeOperation::SSO_DOMAIN_VERIFY->value, null);
        $tenant   = Staff::query()->create(['name' => 'Grace Hopper', 'email' => 'grace@example.test']);

        $tenant->givePermission(AdministrativeOperation::SSO_DOMAIN_VERIFY->value, tenant: new Reference(Organisation::TYPE, self::TENANT));

        $this->check()->authorize(new Subject($platform, $platform), AdministrativeOperation::SSO_DOMAIN_VERIFY, 'sso_domain', 'example.test', self::TENANT);

        $this->expectException(AuthorizationException::class);

        $this->check()->authorize(new Subject($tenant, $tenant), AdministrativeOperation::SSO_DOMAIN_VERIFY, 'sso_domain', 'example.test', self::TENANT);
    }

    /**
     * A subject acting in a tenant `laravel-authorization` cannot read is
     * refused, never decided on the platform.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubjectInATenantThatCannotBeReadIsRefused(): void
    {
        $staff = $this->administrator(AdministrativeOperation::SSO_DOMAIN_CLAIM->value, null);

        $this->expectException(UnresolvedReferenceException::class);

        $this->check()->authorize(new Subject($staff, $staff, new \stdClass), AdministrativeOperation::SSO_DOMAIN_CLAIM, 'sso_domain', 'example.test');
    }

    /**
     * A tenant that resolves to nothing is refused, never checked as the
     * platform's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantThatResolvesToNothingIsRefused(): void
    {
        $staff = $this->administrator(AdministrativeOperation::SSO_DOMAIN_CLAIM->value, null);

        $this->app?->instance(TenantResolver::class, new class implements TenantResolver {
            /**
             * No tenant.
             *
             * @param  string  $tenantId
             * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
             */
            #[\Override]
            public function resolve(string $tenantId): ?Tenant
            {
                return null;
            }
        });

        $this->expectException(UnresolvedReferenceException::class);

        $this->check()->authorize(new Subject($staff, $staff), AdministrativeOperation::SSO_DOMAIN_CLAIM, 'sso_domain', 'example.test', 'missing');
    }

    /**
     * A tenant `laravel-authorization` cannot scope to is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantThatCannotBeScopedIsRefused(): void
    {
        $staff = $this->administrator(AdministrativeOperation::SSO_DOMAIN_CLAIM->value, null);

        $this->app?->instance(TenantResolver::class, new UnscopedTenancy);

        $this->expectException(UnresolvedReferenceException::class);

        $this->check()->authorize(new Subject($staff, $staff), AdministrativeOperation::SSO_DOMAIN_CLAIM, 'sso_domain', 'example.test', self::TENANT);
    }

    /**
     * Name the catalogue among `laravel-authorization`'s permission providers,
     * set before any provider registers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        assert($app instanceof Application);

        $app->make('config')->set('authorization.permission_providers', [PermissionCatalogue::class]);
    }

    /**
     * A person granted the permission, in the tenant or platform-wide.
     *
     * @param  string  $permission
     * @param  ?\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Tests\Fixtures\Authorization\Staff
     */
    private function administrator(string $permission, ?Reference $tenant): Staff
    {
        $staff = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);

        $staff->givePermission($permission, tenant: $tenant);

        return $staff;
    }

    /**
     * The check, as the application resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Authorization\AdministrativeCheck
     */
    private function check(): AdministrativeCheck
    {
        $check = $this->app?->make(AdministrativeCheck::class);

        self::assertInstanceOf(AdministrativeCheck::class, $check);

        return $check;
    }

    /**
     * The person as the request's subject, acting in the tenant.
     *
     * @param  \Tests\Fixtures\Authorization\Staff  $staff
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private static function actingIn(Staff $staff, string $tenantId): Subject
    {
        return new Subject($staff, $staff, new Organisation($tenantId));
    }
}
