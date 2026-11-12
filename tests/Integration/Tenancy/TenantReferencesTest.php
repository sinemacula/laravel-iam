<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\FindsLandlordTenants;
use Tests\Fixtures\Tenancy\LandlordTenant;
use Tests\TestCase;

/**
 * Integration tests for resolving tenant ids through the tenant resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantReferences::class)]
final class TenantReferencesTest extends TestCase
{
    /**
     * The resolver's tenant of the id is the tenant.
     *
     * @return void
     */
    public function testTheResolversTenantOfTheIdIsTheTenant(): void
    {
        $this->app?->instance(TenantResolver::class, new OpenTenancy);

        self::assertSame('tenant-1', $this->references()->tenant('tenant-1')->getTenantIdentifier());
    }

    /**
     * A tenant identified by an integer is the tenant of its digits.
     *
     * @return void
     */
    public function testATenantIdentifiedByAnIntegerIsTheTenantOfItsDigits(): void
    {
        $tenant = \Mockery::mock(Tenant::class);

        $tenant->allows('getTenantIdentifier')->andReturn(42);

        $this->bindResolver($tenant);

        self::assertSame($tenant, $this->references()->tenant('42'));
    }

    /**
     * The default resolver resolves no tenant.
     *
     * @return void
     */
    public function testTheDefaultResolverResolvesNoTenant(): void
    {
        $this->assertUnresolved('tenant-1');
    }

    /**
     * A tenant of another identifier is refused.
     *
     * @return void
     */
    public function testATenantOfAnotherIdentifierIsRefused(): void
    {
        $this->bindResolver(new ClaimedTenant('tenant-2'));

        $this->assertUnresolved('tenant-1');
    }

    /**
     * The resolver is the one bound when asked.
     *
     * @return void
     */
    public function testTheResolverIsTheOneBoundWhenAsked(): void
    {
        $references = $this->references();

        $this->app?->instance(TenantResolver::class, new OpenTenancy);

        self::assertSame('tenant-1', $references->tenant('tenant-1')->getTenantIdentifier());
    }

    /**
     * The resolver's read is pinned to the write connection.
     *
     * @return void
     */
    public function testTheResolversReadIsPinnedToTheWriteConnection(): void
    {
        $this->app?->make('config')->set('database.connections.' . LandlordTenant::CONNECTION, [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
            'read'     => ['database' => ':memory:'],
            'write'    => ['database' => ':memory:'],
        ]);

        $connection = DB::connection(LandlordTenant::CONNECTION);

        foreach ([$connection->getPdo(), $connection->getReadPdo()] as $pdo) {
            $pdo->exec('create table ' . LandlordTenant::TABLE . ' (id varchar(255) not null primary key)');
        }

        $connection->getPdo()->exec('insert into ' . LandlordTenant::TABLE . ' (id) values (\'tenant-1\')');

        $resolver = new FindsLandlordTenants;

        $this->app?->instance(TenantResolver::class, $resolver);

        self::assertNull($resolver->resolve('tenant-1'), 'The replica must lag the primary for this test to prove anything.');
        self::assertSame('tenant-1', $this->references()->tenant('tenant-1')->getTenantIdentifier());
        self::assertNull($resolver->resolve('tenant-1'), 'The connection must read from its replica again once the tenant is resolved.');
    }

    /**
     * Bind a resolver answering the tenant for every id.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return void
     */
    private function bindResolver(Tenant $tenant): void
    {
        $resolver = \Mockery::mock(TenantResolver::class);

        $resolver->allows('resolve')->andReturn($tenant);

        $this->app?->instance(TenantResolver::class, $resolver);
    }

    /**
     * The translator, as the adapters resolve it.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\TenantReferences
     */
    private function references(): TenantReferences
    {
        $references = $this->app?->make(TenantReferences::class);

        self::assertInstanceOf(TenantReferences::class, $references);

        return $references;
    }

    /**
     * Assert the id resolves to no tenant.
     *
     * @param  string  $tenantId
     * @return void
     */
    private function assertUnresolved(string $tenantId): void
    {
        try {
            $this->references()->tenant($tenantId);

            self::fail('The tenant was resolved.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::TENANT, $exception->kind);
            self::assertStringContainsString('[' . $tenantId . ']', $exception->getMessage());
        }
    }
}
