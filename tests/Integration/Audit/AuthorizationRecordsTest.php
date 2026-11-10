<?php

declare(strict_types = 1);

namespace Tests\Integration\Audit;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Iam\Audit\AuditRegistrations;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthorizationEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\GranteeManifests;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\RecordingGrantHook;
use Tests\Fixtures\Authorization\Staff;
use Tests\TestCase;

/**
 * Contract tests pinning the records `laravel-authorization`'s events become
 * (IAM-9.1, IAM-9.2, IAM-9.5): a role created, assigned to two people and
 * deleted is three records of one call each, each correlated by its call, the
 * deletion carrying both grantees as its manifest; a permission granted and
 * revoked is two; a denied check is one record, an `authorize()` that throws is
 * one more, never two, and an allowed check is none. The records reach
 * audit-log's fake store through its whole capture pipeline, which refuses a
 * code no definition registers, so every code is proven defined.
 *
 * Every grant is written inside `laravel-authorization`'s transaction, so each
 * sequence runs at the connection's own level on every engine, then at READ
 * COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditRegistrations::class)]
#[CoversClass(AuthorizationEventMapper::class)]
#[CoversClass(GranteeManifests::class)]
#[WithConfig('audit-log.definitions.require_registered', true)]
final class AuthorizationRecordsTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /** @var \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore The store the records reach. */
    private FakeAuditStore $store;

    /**
     * Store the invoice permissions, record grant hooks rather than widen
     * anyone's scope, and keep the records in the fake store.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        foreach (InvoicePermission::cases() as $permission) {
            Permission::query()->create(['name' => $permission->value]);
        }

        $this->app?->instance(GrantHook::class, new RecordingGrantHook);

        $this->store = AuditLog::fake();
    }

    /**
     * A role created, assigned to two people and deleted is recorded, each
     * change once, correlated by its own call, and the deletion carries both
     * grantees as its manifest.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARolesLifeIsRecordedCallByCall(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $roles = $this->app?->make(RoleService::class);
        $ada   = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);
        $grace = Staff::query()->create(['name' => 'Grace Hopper', 'email' => 'grace@example.test']);

        self::assertInstanceOf(RoleService::class, $roles);

        $role = $roles->create('billing');

        $ada->assignRole($role);
        $grace->assignRole($role);
        $roles->delete($role);

        $records = $this->changes();

        $codes = ['authorization.role_created', 'authorization.role_assigned', 'authorization.role_assigned', 'authorization.role_deleted'];

        self::assertSame($codes, array_column($records, 'event'));
        self::assertCount(4, array_unique(array_column($records, 'correlation_id')));
        self::assertStringStartsWith('authorization:', (string) $records[0]['correlation_id']);
        self::assertSame([null, null, null, 2], array_column($records, 'manifest'));
        self::assertSame(2, $records[3]['properties']['grantee_count'] ?? null);

        foreach ($records as $record) {
            self::assertNull($record['actor']);
            self::assertNull($record['tenant']);
            self::assertTrue($record['properties']['trusted'] ?? null);
        }
    }

    /**
     * A permission granted and revoked is two records about the grantee.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPermissionGrantedAndRevokedIsTwoRecords(): void
    {
        $ada = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);

        $ada->givePermission(InvoicePermission::REFUND->value);
        $ada->revokePermission(InvoicePermission::REFUND->value);

        $records = $this->changes();

        self::assertSame(['authorization.permission_assigned', 'authorization.permission_unassigned'], array_column($records, 'event'));
        self::assertSame([Staff::class, self::keyOf($ada)], $records[0]['subject']);
        self::assertSame(InvoicePermission::REFUND->value, $records[1]['properties']['name'] ?? null);
    }

    /**
     * A denied check is one record, a denial `authorize()` throws one more,
     * never two, and an allowed check none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachDenialIsRecordedOnceAndNoAllow(): void
    {
        $ada = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);

        $ada->givePermission(InvoicePermission::VOID->value);

        self::assertFalse(Authorization::forUser($ada)->can(InvoicePermission::REFUND->value));
        self::assertTrue(Authorization::forUser($ada)->can(InvoicePermission::VOID->value));

        try {
            Authorization::forUser($ada)->authorize(InvoicePermission::REFUND->value, 'invoice:9');
            self::fail('The refund was allowed.');
        } catch (AuthorizationException) {
            // The denial is what this test checks.
        }

        $denials = $this->store->recorded(static fn (AuditRecord $record): bool => str_starts_with($record->event, 'authorization.access'));

        self::assertSame(['authorization.access_denied', 'authorization.access_denied'], array_map(static fn (AuditRecord $record): string => $record->event, $denials));
        self::assertSame(['no_match', 'no_match'], array_map(static fn (AuditRecord $record): ?string => $record->reason, $denials));
        self::assertSame('invoice:9', $denials[1]->properties['resource'] ?? null);
        self::assertSame('security', $denials[1]->category);
    }

    /**
     * Declare the invoice permissions, set before any provider registers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        assert($app instanceof Application);

        $app->make('config')->set('authorization.permission_enums', [InvoicePermission::class]);
    }

    /**
     * Every change recorded, in order, with what the tests read of it.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return list<array{event: string, correlation_id: ?string, actor: ?array{0: string, 1: string}, subject: ?array{0: string, 1: string}, tenant: ?array{0: string, 1: string}, properties: array<string, mixed>, manifest: ?int}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function changes(): array
    {
        $records = $this->store->recorded(static fn (AuditRecord $record): bool => $record->category === 'access_management');

        return array_map(static fn (AuditRecord $record): array => [
            'event'          => $record->event,
            'correlation_id' => $record->correlationId,
            'actor'          => $record->actorType   === null ? null : [$record->actorType, (string) $record->actorId],
            'subject'        => $record->subjectType === null ? null : [$record->subjectType, (string) $record->subjectId],
            'tenant'         => $record->tenantType  === null ? null : [$record->tenantType, (string) $record->tenantId],
            'properties'     => $record->properties ?? [],
            'manifest'       => $record->attachment?->memberCount,
        ], $records);
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
