<?php

declare(strict_types = 1);

namespace Tests\Integration\Audit;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Iam\Authorization\AuditAccessPolicyAdapter;
use SineMacula\Laravel\Iam\Authorization\PermissionCatalogue;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Concerns\MigratesAuditLog;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Authorization\RecordingGrantHook;
use Tests\Fixtures\Authorization\Staff;
use Tests\TestCase;

/**
 * End-to-end tests of `laravel-authorization` and the audit trail, with
 * audit-log storing in its own tables on the storage connection beside
 * `laravel-authorization`'s (IAM-6.10, IAM-9.2): a viewer reads exactly the
 * tenants its grants reach, never another tenant's entries nor the entries with
 * no tenant, and a viewer granted nothing reads nothing; and a denial made
 * inside a transaction on the storage connection that rolls back is still
 * recorded, once, after the rollback, as one made inside a transaction that
 * commits is, after the commit.
 *
 * Each runs at the connection's own level on every engine, then at READ
 * COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditAccessPolicyAdapter::class)]
final class AuthorizationTrailTest extends TestCase
{
    use MigratesAuditLog, RunsAtIsolationLevels;

    /** @var string The code the application's own entries are recorded under. */
    private const string VIEWED = 'invoice.viewed';

    /** @var string The code a denial is recorded under. */
    private const string DENIED = 'authorization.access_denied';

    /**
     * Store the permissions, so they can be granted, record grant hooks rather
     * than widen anyone's scope, and resolve the organisations.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        foreach ([...(new PermissionCatalogue)->permissions()] as $definition) {
            Permission::query()->create(['name' => $definition->name]);
        }

        foreach (InvoicePermission::cases() as $permission) {
            Permission::query()->create(['name' => $permission->value]);
        }

        $this->app?->instance(GrantHook::class, new RecordingGrantHook);
        $this->app?->singleton(TenantResolver::class, OrganisationTenancy::class);
    }

    /**
     * A viewer reads exactly the tenants its grants reach, and a viewer granted
     * nothing reads nothing.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAViewerNeverReadsBeyondItsScope(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $viewer = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);
        $nobody = Staff::query()->create(['name' => 'Grace Hopper', 'email' => 'grace@example.test']);

        FakeMemberships::fake($this->app)
            ->grant($viewer, Membership::of('org-1'))
            ->grant($viewer, Membership::of('org-2'))
            ->grant($nobody, Membership::of('org-1'));

        $viewer->givePermission('audit-log.count', tenant: new Reference(Organisation::TYPE, 'org-1'));

        foreach (['org-1', 'org-1', 'org-2', null] as $tenantId) {
            AuditLog::event(self::VIEWED)->forTenant(References::tenant($tenantId))->record();
        }

        self::assertSame(2, AuditLog::trail()->forEvent(self::VIEWED)->visibleTo($viewer)->count());
        self::assertSame(0, AuditLog::trail()->forEvent(self::VIEWED)->visibleTo($nobody)->count());
    }

    /**
     * A denial made inside a transaction on the storage connection is recorded
     * once that transaction has ended: after a rollback, which would have taken
     * a record written at once with it, as after a commit.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testADenialInsideATransactionIsRecordedOnceItEnds(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $staff = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);

        try {
            DB::transaction(static function () use ($staff): void {

                self::assertFalse(Authorization::forUser($staff)->can(InvoicePermission::REFUND->value));
                self::assertSame(0, self::denials());

                throw new \RuntimeException('Roll the work back.');
            });
        } catch (\RuntimeException) {
            // The rollback is what this test checks.
        }

        self::assertSame(1, self::denials());

        DB::transaction(static function () use ($staff): void {

            self::assertFalse(Authorization::forUser($staff)->can(InvoicePermission::VOID->value));
            self::assertSame(1, self::denials());
        });

        self::assertSame(2, self::denials());
    }

    /**
     * Run the fixtures' migrations and every member's audit-log's tests run,
     * with `laravel-authorization`'s, which it only publishes, beside them.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(dirname(__DIR__, 2) . '/Fixtures/database/migrations');

        $providers = [
            AuthenticationServiceProvider::class,
            MfaServiceProvider::class,
            SsoServiceProvider::class,
            AuditLogServiceProvider::class,
            AuthorizationServiceProvider::class,
        ];

        foreach ($providers as $provider) {

            $file = (new \ReflectionClass($provider))->getFileName();

            assert(is_string($file));

            $this->loadMigrationsFrom(dirname($file, 2) . '/database/migrations');
        }
    }

    /**
     * Name the catalogue and declare the invoice permissions, set before any
     * provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $app->make('config')->set('authorization.permission_providers', [PermissionCatalogue::class]);
        $app->make('config')->set('authorization.permission_enums', [InvoicePermission::class]);
    }

    /**
     * How many denials the trail holds.
     *
     * @return int
     */
    private static function denials(): int
    {
        return DB::table('audit_log_entries')->where('event', self::DENIED)->count();
    }
}
