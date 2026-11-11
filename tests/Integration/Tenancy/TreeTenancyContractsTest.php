<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use Tests\Concerns\MigratesAuthorization;
use Tests\Fixtures\Authorization\Account;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Integration tests for reading `laravel-authorization`'s tenant tree
 * (IAM-7.5): its flat default is no tree, the application's is, and a subtree's
 * typed rows are read from a query or an Eloquent builder, anything else
 * refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenancyContracts::class)]
final class TreeTenancyContractsTest extends TestCase
{
    use MigratesAuthorization;

    /**
     * `laravel-authorization`'s flat default is no tree.
     *
     * @return void
     */
    public function testTheFlatDefaultIsNoTree(): void
    {
        self::assertNull($this->contracts()->tree());
        self::assertFalse(TenancyContracts::hasTree());
    }

    /**
     * The application's tree is read, and its subtree lists the tenant and
     * every tenant below it, of whatever type.
     *
     * @return void
     */
    public function testTheApplicationsTreeIsRead(): void
    {
        $organisation = new Reference(Organisation::TYPE, '1');
        $account      = new Reference(Account::TYPE, '1');
        $tree         = new StoredTenantTree;

        StoredTenantTree::place($organisation);
        StoredTenantTree::place($account, $organisation);

        $this->app?->instance(TenantTree::class, $tree);

        self::assertSame($tree, $this->contracts()->tree());
        self::assertTrue(TenancyContracts::hasTree());
        self::assertEquals([$organisation, $account], $this->contracts()->subtree($organisation));
    }

    /**
     * A subtree answered as an Eloquent builder is read through its query.
     *
     * @return void
     */
    public function testAnEloquentSubtreeIsRead(): void
    {
        $organisation = new Reference(Organisation::TYPE, '1');
        $nodes        = new class extends Model {
            /** @var ?string The table the tree is kept in. */
            protected $table = StoredTenantTree::TABLE;
        };

        StoredTenantTree::place($organisation);

        $this->bindSubtree($nodes->newQuery()->select(['tenant_type', 'tenant_id']));

        self::assertEquals([$organisation], $this->contracts()->subtree($organisation));
    }

    /**
     * A subtree that is no query is refused, naming its class.
     *
     * @return void
     */
    public function testASubtreeThatIsNoQueryIsRefused(): void
    {
        $subtree = \Mockery::mock(Builder::class);

        $this->bindSubtree($subtree);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('The tenant tree answered a subtree of [' . $subtree::class . '], which is no query.');

        $this->contracts()->subtree(new Reference(Organisation::TYPE, '1'));
    }

    /**
     * Bind a tree whose every subtree is the one given.
     *
     * @param  \Illuminate\Contracts\Database\Query\Builder  $subtree
     * @return void
     */
    private function bindSubtree(Builder $subtree): void
    {
        $tree = \Mockery::mock(TenantTree::class);

        $tree->allows('subtree')->andReturn($subtree);

        $this->app?->instance(TenantTree::class, $tree);
    }

    /**
     * The finder under test.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\TenancyContracts
     */
    private function contracts(): TenancyContracts
    {
        return $this->app?->make(TenancyContracts::class) ?? self::fail('The application has not booted.');
    }
}
