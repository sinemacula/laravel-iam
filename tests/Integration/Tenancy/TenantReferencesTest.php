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
 * Integration tests for resolving the tenants a member names by opaque id to
 * `laravel-authentication`'s tenants, through `laravel-authentication`'s own
 * tenant resolver as the application binds it, asked with its reads pinned to
 * the write connection: a tenant of exactly that identifier, and otherwise a
 * refusal by throwing (IAM-8.2).
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
     * The tenant the application's resolver answers under the id given is the
     * tenant.
     *
     * @return void
     */
    public function testTheResolversTenantOfTheIdIsTheTenant(): void
    {
        $this->app?->instance(TenantResolver::class, new OpenTenancy);

        self::assertSame('tenant-1', $this->references()->tenant('tenant-1')->getTenantIdentifier());
    }

    /**
     * A tenant identified by an integer is the tenant of the id that integer is
     * written as, as `laravel-authentication` matches a session's tenant.
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
     * With `laravel-authentication`'s default resolver, which resolves no
     * tenant, every tenant is refused by throwing.
     *
     * @return void
     */
    public function testTheDefaultResolverResolvesNoTenant(): void
    {
        $this->assertUnresolved('tenant-1');
    }

    /**
     * A resolver answering a tenant of another identifier would have another
     * tenant's sessions judged, so the tenant is refused by throwing.
     *
     * @return void
     */
    public function testATenantOfAnotherIdentifierIsRefused(): void
    {
        $this->bindResolver(new ClaimedTenant('tenant-2'));

        $this->assertUnresolved('tenant-1');
    }

    /**
     * The resolver is asked as the application binds it when the question is
     * asked, not as it was bound when the translator was built.
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
     * A resolver that reads the tenant with a plain model query, relying on the
     * pin `laravel-authentication`'s contract promises, is asked with its reads
     * on the write connection, wherever the tenant lives: a tenant the primary
     * holds and its replica has not yet seen is the tenant, not a refusal that
     * would roll back the change SSO was making.
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
     * Assert the id resolves to no tenant: it throws an unresolved tenant,
     * naming the id.
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
