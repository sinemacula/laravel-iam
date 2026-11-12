<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

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
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
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
 * Integration tests for the check before an administrative operation.
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
     * Store the permissions, record grant hooks and resolve organisations.
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
     * A grant in the object's tenant allows the operation only there.
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
     * A denial throws before the operation and is recorded once.
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
     * A refusal for want of a proof on no session is recorded once.
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
     * An operation on the type is checked on the type.
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
     * A subject with no tenant is decided on the platform.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubjectWithNoTenantIsDecidedOnThePlatform(): void
    {
        $platform = $this->administrator(AdministrativeOperation::SSO_DOMAIN_VERIFY->value, null);
        $tenant   = Staff::query()->create(['name' => 'Grace Hopper', 'email' => 'grace@example.test']);
        $request  = AuthorizationScope::tenant(new Reference(Organisation::TYPE, self::TENANT));

        $tenant->givePermission(AdministrativeOperation::SSO_DOMAIN_VERIFY->value, tenant: new Reference(Organisation::TYPE, self::TENANT));

        $decided = $request->within(function () use ($platform, $tenant): array {

            $this->check()->authorize(new Subject($platform, $platform), AdministrativeOperation::SSO_DOMAIN_VERIFY, 'sso_domain', 'example.test', self::TENANT);

            $afterAllow = AuthorizationScope::current();

            try {
                $this->check()->authorize(new Subject($tenant, $tenant), AdministrativeOperation::SSO_DOMAIN_VERIFY, 'sso_domain', 'example.test', self::TENANT);
                self::fail('The subject was decided in the request\'s tenant.');
            } catch (AuthorizationException) {
                // The denial is what this test checks.
            }

            return [$afterAllow, AuthorizationScope::current()];
        });

        self::assertEquals([$request, $request], $decided);
    }

    /**
     * A subject in a tenant is decided there, whatever the request's tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubjectInATenantIsDecidedThereWhateverTheRequestsTenant(): void
    {
        $staff   = $this->administrator(AdministrativeOperation::SSO_DOMAIN_VERIFY->value, new Reference(Organisation::TYPE, self::TENANT));
        $request = AuthorizationScope::tenant(new Reference(Organisation::TYPE, self::OTHER));

        $decided = $request->within(function () use ($staff): AuthorizationScope {

            $this->check()->authorize(self::actingIn($staff, self::TENANT), AdministrativeOperation::SSO_DOMAIN_VERIFY, 'sso_domain', 'example.test', self::TENANT);

            return AuthorizationScope::current();
        });

        self::assertEquals($request, $decided);
    }

    /**
     * A subject in a tenant authorization cannot read is refused.
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
     * A tenant that resolves to nothing is refused.
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
     * Register the catalogue as a permission provider.
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
