<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\TenantTreeAdapter;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Contracts\TenantTree as ApplicationTree;
use SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\TreeChanges;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Account;
use Tests\Fixtures\Authorization\AccountTenancy;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\Member;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Authorization\SeatHolder;
use Tests\Fixtures\Authorization\TenantInvoice;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authorization`'s tenant tree, answered from
 * the application's one tree (IAM-7.5, AUTHZ-5.3, AUTHZ-12.8): the ancestors,
 * containment and subtree `laravel-authorization` reads are the application's
 * tree's, named by the type of the tenant asked about, the subtree a query on
 * the tree's own connection selecting each tenant's type and id, the id as text
 * in every grammar; without a tree `laravel-authorization`'s own flat tree is
 * read, so a record on another connection than the grants is scoped by its
 * tenant, and the adapter, asked with none, refuses; a subtree that is no query
 * builder is refused; a tree that nests two tenant types is refused; and a move
 * the application reports reaches `laravel-authorization`, so a grant made at
 * the new ancestor holds in the moved tenant at once, while one not reported is
 * still read from the tree as `laravel-authorization` last cached it; with the
 * authorization capability off, nothing is reported to it, and a tenant that
 * cannot be named to it refuses the move.
 *
 * The subtree is read inside a transaction, as `laravel-authorization` reads it
 * inside its own, at the connection's own level on every engine, then at READ
 * COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantTreeAdapter::class)]
#[CoversClass(TreeChanges::class)]
#[CoversClass(TenantTranslator::class)]
#[CoversClass(TenancyMisconfiguredException::class)]
final class TenantTreeAdapterTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The root the moved tenant comes to stand below. */
    private const string ROOT = 'root';

    /** @var string The tenant that moves. */
    private const string MOVED = 'moved';

    /** @var string The moved tenant's child. */
    private const string CHILD = 'moved-child';

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeTenantTree The application's tree. */
    private ?FakeTenantTree $tree = null;

    /**
     * Arrange the tree, the moved tenant and its child standing apart from the
     * root, and resolve every tenant to the organisation of its id.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->tree = FakeTenantTree::fake($this->app)->place(self::ROOT)->place(self::MOVED)->place(self::CHILD, self::MOVED);

        $this->app?->instance(TenantResolver::class, new OrganisationTenancy);

        foreach (InvoicePermission::cases() as $permission) {
            Permission::query()->create(['name' => $permission->value]);
        }
    }

    /**
     * The adapter is the tree `laravel-authorization` reads, and answers the
     * application's tree's ancestors and containment, named by the type of the
     * tenant asked about.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testItAnswersTheApplicationsTree(): void
    {
        $this->tree()->place(self::MOVED, self::ROOT);

        $adapter = $this->adapter();

        self::assertInstanceOf(TenantTreeAdapter::class, $adapter);
        self::assertEquals([self::organisation(self::MOVED), self::organisation(self::ROOT)], $adapter->ancestors(self::organisation(self::CHILD)));
        self::assertSame([], $adapter->ancestors(self::organisation(self::ROOT)));
        self::assertTrue($adapter->isWithin(self::organisation(self::CHILD), self::organisation(self::ROOT)));
        self::assertTrue($adapter->isWithin(self::organisation(self::ROOT), self::organisation(self::ROOT)));
        self::assertFalse($adapter->isWithin(self::organisation(self::ROOT), self::organisation(self::CHILD)));
        self::assertFalse($adapter->isWithin(new Reference('another-type', self::CHILD), self::organisation(self::ROOT)));
    }

    /**
     * A tenant whose key, resolved as an identifier, names a tenant of another
     * type is never read as that tenant's place in the tree: asking its
     * ancestors, its subtree or whether it is within another tenant of its type
     * is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantThatDoesNotResolveBackIsRefused(): void
    {
        $adapter   = $this->adapter();
        $elsewhere = new Reference('another-type', self::CHILD);
        $refusals  = [
            static fn (): mixed => $adapter->ancestors($elsewhere),
            static fn (): mixed => $adapter->subtree($elsewhere),
            static fn (): mixed => $adapter->isWithin($elsewhere, new Reference('another-type', self::MOVED)),
        ];

        foreach ($refusals as $refusal) {
            try {
                $refusal();

                self::fail('A tenant that does not resolve back was read from the tree.');
            } catch (UnresolvedReferenceException) {
                // Refused.
            }
        }

        self::assertCount(3, $refusals);
    }

    /**
     * The subtree is a query of the tenant and every tenant below it, selecting
     * each one's type and id, read inside a transaction at every isolation
     * level.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheSubtreeSelectsEachTenantsTypeAndId(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $rows = DB::transaction(fn (): array => $this->adapter()->subtree(self::organisation(self::MOVED))->get()->map(static fn (object $row): array => (array) $row)->all());

        usort($rows, static fn (array $left, array $right): int => strcmp((string) $left['tenant_id'], (string) $right['tenant_id']));

        self::assertSame([
            ['tenant_type' => Organisation::TYPE, 'tenant_id' => self::MOVED],
            ['tenant_type' => Organisation::TYPE, 'tenant_id' => self::CHILD],
        ], array_map(static fn (array $row): array => ['tenant_type' => $row['tenant_type'], 'tenant_id' => $row['tenant_id']], $rows));
    }

    /**
     * The tenants of the subtree are listed each as the tenant resolver names
     * it, the tenant itself among them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSubtreesTenantsAreListed(): void
    {
        $adapter = $this->adapter();

        self::assertInstanceOf(TenantTreeAdapter::class, $adapter);

        $listed = $adapter->tenantsIn(self::organisation(self::MOVED));

        usort($listed, static fn (Reference $left, Reference $right): int => strcmp($left->id, $right->id));

        self::assertEquals([self::organisation(self::MOVED), self::organisation(self::CHILD)], $listed);
    }

    /**
     * A tree that places a tenant below one of another type, an account below
     * an organisation, is refused wherever the adapter meets it: the account's
     * ancestors, and the organisation's tenants, either way round, since the
     * subtree, naming every tenant by the organisation's type, would match none
     * of the account's grants; the two are never within one another.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATreeNestingTwoTenantTypesIsRefused(): void
    {
        $account = Account::PREFIX . '1';

        $this->tree()->place($account, self::CHILD);
        $this->app?->instance(TenantResolver::class, new AccountTenancy);

        $adapter  = $this->adapter();
        $below    = new Reference(Account::TYPE, $account);
        $refusals = [
            static fn (): mixed => $adapter->ancestors($below),
            static fn (): mixed => $adapter instanceof TenantTreeAdapter ? $adapter->tenantsIn(self::organisation(self::MOVED)) : null,
        ];

        self::assertFalse($adapter->isWithin($below, self::organisation(self::CHILD)));

        foreach ($refusals as $refusal) {
            try {
                $refusal();

                self::fail('A tree nesting two tenant types was read.');
            } catch (TenancyMisconfiguredException $exception) {
                self::assertStringContainsString('[' . Account::TYPE . ']', $exception->getMessage());
                self::assertStringContainsString('[' . Organisation::TYPE . ']', $exception->getMessage());
            }
        }

        self::assertSame([], $adapter->ancestors(self::organisation(self::ROOT)));
    }

    /**
     * An Eloquent subtree is nested as its query, and one that is no query
     * builder at all is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubtreeIsNestedOnlyWhenItIsAQuery(): void
    {
        $eloquent = \Mockery::mock(ApplicationTree::class);
        $other    = \Mockery::mock(ApplicationTree::class);

        $relation = \Mockery::mock(ApplicationTree::class);

        $eloquent->allows('subtree')->andReturn(Person::query()->select('id as ' . ApplicationTree::ID_COLUMN));
        $relation->allows('subtree')->andReturn((new SeatHolder)->principals()->select(ApplicationTree::ID_COLUMN));
        $other->allows('subtree')->andReturn(\Mockery::mock(Builder::class));

        $this->app?->instance(ApplicationTree::class, $eloquent);

        self::assertCount(0, $this->adapter()->subtree(self::organisation(self::ROOT))->get());

        $this->app?->instance(ApplicationTree::class, $relation);

        self::assertCount(0, $this->adapter()->subtree(self::organisation(self::ROOT))->get());

        $this->app?->instance(ApplicationTree::class, $other);

        $this->expectException(\LogicException::class);

        $this->adapter()->subtree(self::organisation(self::ROOT));
    }

    /**
     * Without an application tree, `laravel-authorization`'s own flat tree is
     * the one it reads, which it tells a flat application by: a record kept on
     * another connection than its grants is scoped by its tenant column alone,
     * rather than by a subtree query `laravel-authorization` refuses to nest
     * across connections.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testWithoutATreeARecordOnAnotherConnectionIsScopedByItsTenant(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->withoutATree();
        $this->createInvoices();

        $person = Member::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);
        $tree   = $this->adapter();

        $this->grantIn($person, self::MOVED);

        TenantInvoice::query()->insert([
            ['id' => 1, 'tenant_type' => Organisation::TYPE, 'tenant_id' => self::MOVED],
            ['id' => 2, 'tenant_type' => Organisation::TYPE, 'tenant_id' => self::ROOT],
            ['id' => 3, 'tenant_type' => Organisation::TYPE, 'tenant_id' => self::CHILD],
        ]);

        // audit-log's capture listens to every event, which
        // laravel-authorization takes for a listener of the record's retrieval
        // and refuses to scope a query for, so it is forgotten here
        Event::forget('*');

        $authorization = $this->app?->make(AuthorizationManager::class) ?? self::fail('The application has not booted.');
        $subject       = $authorization->forUser($person);
        $scoped        = static fn (): array => TenantInvoice::query()->whereAuthorized(InvoicePermission::REFUND->value, [], $subject)->orderBy('id')->pluck('id')->all();
        $refundable    = array_map(intval(...), DB::transaction(static fn (): array => TenantScope::within(new Organisation(self::MOVED), null, $scoped)));

        self::assertInstanceOf(FlatTenantTree::class, $tree);
        self::assertSame([1], $refundable);
    }

    /**
     * The adapter is never bound without a tree, and asked with none, which
     * only a tree taken away within the unit of work leaves it, it refuses
     * rather than answer as though every tenant stood alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAskedWithNoTreeTheAdapterRefuses(): void
    {
        $adapter = $this->adapter();

        $this->withoutATree();

        $refusals = [
            static fn (): mixed => $adapter->ancestors(self::organisation(self::CHILD)),
            static fn (): mixed => $adapter->isWithin(self::organisation(self::CHILD), self::organisation(self::MOVED)),
            static fn (): mixed => $adapter->subtree(self::organisation(self::CHILD)),
        ];

        self::assertInstanceOf(TenantTreeAdapter::class, $adapter);

        foreach ($refusals as $refusal) {
            try {
                $refusal();

                self::fail('The adapter answered with no tree.');
            } catch (TenancyMisconfiguredException $exception) {
                self::assertStringContainsString(ApplicationTree::class, $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[connection driver, the cast the subtree selects each id with]`:
     * the text type of each grammar.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function provideGrammars(): iterable
    {
        yield 'MySQL' => ['mysql', 'CAST(`iam_subtree`.`tenant_id` AS CHAR) as `tenant_id`'];

        yield 'MariaDB' => ['mariadb', 'CAST(`iam_subtree`.`tenant_id` AS CHAR) as `tenant_id`'];

        yield 'PostgreSQL' => ['pgsql', 'CAST("iam_subtree"."tenant_id" AS VARCHAR) as "tenant_id"'];

        yield 'SQLite' => ['sqlite', 'CAST("iam_subtree"."tenant_id" AS TEXT) as "tenant_id"'];
    }

    /**
     * The subtree selects each id as text, in the grammar of the connection the
     * application's tree queries, whatever type the tree selects it as.
     *
     * @param  string  $driver
     * @param  string  $cast
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideGrammars')]
    public function testTheSubtreeSelectsEachIdAsText(string $driver, string $cast): void
    {
        $name = 'tree_' . $driver;
        $tree = \Mockery::mock(ApplicationTree::class);

        $this->app?->make('config')->set('database.connections.' . $name, ['driver' => $driver, 'database' => 'unused', 'host' => '127.0.0.1', 'prefix' => '']);

        $tree->allows('subtree')->andReturn(DB::connection($name)->query()->from('tenants')->select('id as ' . ApplicationTree::ID_COLUMN));

        $this->app?->instance(ApplicationTree::class, $tree);

        self::assertStringContainsString($cast, $this->adapter()->subtree(self::organisation(self::ROOT))->toSql());

        DB::purge($name);
    }

    /**
     * A move the application reports reaches `laravel-authorization`: a grant
     * made at the root, reaching below it, holds in the moved tenant and its
     * child once the move is reported, while a move not yet reported is read
     * from the tree as `laravel-authorization` last cached it.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAReportedMoveReachesAuthorization(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = Member::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);

        $this->grantAtTheRoot($person);

        self::assertFalse($this->mayRefundIn($person, self::MOVED));

        $this->tree()->place(self::MOVED, self::ROOT);

        self::assertFalse($this->mayRefundIn($person, self::MOVED), 'laravel-authorization read the tree afresh without the move being reported.');

        self::assertSame(0, Iam::transaction(static fn (): int => Iam::treeChanges()->changed(self::MOVED)));

        self::assertTrue($this->mayRefundIn($person, self::MOVED));
        self::assertTrue($this->mayRefundIn($person, self::CHILD));
    }

    /**
     * A check in a tenant two levels below the grant reads the application's
     * tree once: `laravel-authorization` keeps the tenant's chain, and its
     * batch memo of tree reads, against the tree instance it read them from, so
     * the tree bound is one instance for the unit of work; a check in a fresh
     * unit of work reads it once again. No cache store is configured, so no
     * cached resolution reads the chain again to pin it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACheckReadsTheTreeOncePerUnitOfWork(): void
    {
        $this->tree()->place(self::MOVED, self::ROOT);

        $person = Member::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);

        $this->grantAtTheRoot($person);

        Config::set('authorization.cache.store', null);

        Iam::resetWorkerState();

        $before = $this->ancestorsRead();

        self::assertTrue($this->mayRefundIn($person, self::CHILD));
        self::assertSame(1, $this->ancestorsRead() - $before);

        Iam::resetWorkerState();

        self::assertTrue($this->mayRefundIn($person, self::CHILD));
        self::assertSame(2, $this->ancestorsRead() - $before);
    }

    /**
     * With the authorization capability off, nothing is reported to
     * `laravel-authorization`, and no tenant is resolved for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithTheSwitchOffNothingIsReportedToAuthorization(): void
    {
        $resolver = \Mockery::mock(TenantResolver::class);

        $resolver->expects('resolve')->never();

        $this->app?->instance(TenantResolver::class, $resolver);

        Config::set(AuthorizationSeams::SWITCH, false);

        self::assertSame(0, Iam::transaction(static fn (): int => Iam::treeChanges()->changed(self::MOVED)));
    }

    /**
     * Without a tree, `laravel-authorization` keeps its own flat tree, which no
     * move changes, so nothing is reported to it, and no tenant is resolved for
     * it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutATreeNothingIsReportedToAuthorization(): void
    {
        $resolver = \Mockery::mock(TenantResolver::class);

        $resolver->expects('resolve')->never();

        $this->app?->instance(TenantResolver::class, $resolver);

        $this->withoutATree();

        self::assertSame(0, Iam::transaction(static fn (): int => Iam::treeChanges()->changed(self::MOVED)));
    }

    /**
     * A tenant that cannot be named to `laravel-authorization` refuses the
     * move, rather than leave its cached chains standing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantThatCannotBeNamedRefusesTheMove(): void
    {
        $resolver = \Mockery::mock(TenantResolver::class);

        $resolver->allows('resolve')->andReturnNull();

        $this->app?->instance(TenantResolver::class, $resolver);

        $this->expectException(UnresolvedReferenceException::class);

        Iam::transaction(static fn (): int => Iam::treeChanges()->changed(self::MOVED));
    }

    /**
     * Declare the invoice permissions, and keep `laravel-authorization`'s
     * resolutions in a store that outlives a check, as a worker's would, set
     * before any provider registers.
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
        $app->make('config')->set('authorization.cache.store', 'array');
    }

    /**
     * Take the application's tree away, as an application that names none, from
     * the next unit of work.
     *
     * @return void
     */
    private function withoutATree(): void
    {
        $this->app?->forgetInstance(ApplicationTree::class);
        $this->app?->offsetUnset(ApplicationTree::class);

        Iam::resetWorkerState();
    }

    /**
     * Create the invoices' table on their own connection, a second connection
     * to the test's database, dropped once the test ends.
     *
     * @return void
     */
    private function createInvoices(): void
    {
        $config = $this->app?->make('config') ?? self::fail('The application has not booted.');

        $config->set('database.connections.' . TenantInvoice::CONNECTION, $config->get('database.connections.' . DB::getDefaultConnection()));

        Schema::connection(TenantInvoice::CONNECTION)->create(TenantInvoice::TABLE, static function (Blueprint $table): void {
            $table->unsignedInteger('id')->primary();
            $table->string('tenant_type', 191);
            $table->string('tenant_id', 191);
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::connection(TenantInvoice::CONNECTION)->dropIfExists(TenantInvoice::TABLE);
            DB::purge(TenantInvoice::CONNECTION);
        });
    }

    /**
     * Grant the person the refund in the tenant alone.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $person
     * @param  string  $tenantId
     * @return void
     *
     * @throws \Throwable
     */
    private function grantIn(Member $person, string $tenantId): void
    {
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        $service->grantPermission($person, InvoicePermission::REFUND->value, tenant: self::organisation($tenantId), includeSubtree: false);
    }

    /**
     * Grant the person the refund at the root, reaching every tenant below it.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $person
     * @return void
     *
     * @throws \Throwable
     */
    private function grantAtTheRoot(Member $person): void
    {
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        $service->grantPermission($person, InvoicePermission::REFUND->value, tenant: self::organisation(self::ROOT), includeSubtree: true);
    }

    /**
     * Whether the person may refund in the tenant, as `laravel-authorization`
     * lists the person's permissions there.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $person
     * @param  string  $tenantId
     * @return bool
     */
    private function mayRefundIn(Member $person, string $tenantId): bool
    {
        $authorization = $this->app?->make(AuthorizationManager::class) ?? self::fail('The application has not booted.');

        return in_array(InvoicePermission::REFUND->value, $authorization->permissionsFor($person, AuthorizationScope::tenant(self::organisation($tenantId))), true);
    }

    /**
     * How many times the application's tree has been asked a tenant's ancestors
     * so far.
     *
     * @return int
     */
    private function ancestorsRead(): int
    {
        return count(array_filter($this->tree()->asked(), static fn (array $question): bool => $question['question'] === 'ancestors'));
    }

    /**
     * The tree `laravel-authorization` reads.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\TenantTree
     */
    private function adapter(): TenantTree
    {
        return $this->app?->make(TenantTree::class) ?? self::fail('The application has not booted.');
    }

    /**
     * The application's tree.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeTenantTree
     */
    private function tree(): FakeTenantTree
    {
        return $this->tree ?? self::fail('The tree is not arranged.');
    }

    /**
     * `laravel-authorization`'s reference to the organisation of the id.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function organisation(string $id): Reference
    {
        return new Reference(Organisation::TYPE, $id);
    }
}
