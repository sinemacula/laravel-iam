<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\Iam\Contracts\TenantTree;

/**
 * A tenant tree for tests: each tenant sits where the test placed it
 * (`place()`), under the parent given or as a root, and a tenant the test told
 * it to fail for throws (`failFor()`), as an application's tree that cannot be
 * read does.
 *
 * A tenant is placed once and moved by placing it again; a parent that is the
 * tenant itself, or any tenant below it, would make a cycle, and is refused. A
 * tenant removed (`remove()`) leaves its children under its own parent, or as
 * roots. A tenant never placed has no ancestors and no descendants. The subtree
 * is a query of the tenant and its descendants, on the default database
 * connection unless another is named, selecting their ids in the `tenant_id`
 * column. Each question is kept (`asked()`).
 *
 * Call `FakeTenantTree::fake()`, which binds a fresh instance as the
 * application's tree and returns it. A binding made once the package has
 * registered is the one asked, but binds no enforcement inheritance: name the
 * class in `iam.tenancy.tree` as well, before the application boots, for the
 * adapter to be bound over SSO's default. Report a move the way the application
 * would (`Iam::treeChanges()->changed()`). It satisfies this package's own
 * `Seams\Concerns\TenantTreeTests` kit. Not for production use.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeTenantTree implements TenantTree
{
    /** @var class-string The contract the fake is bound as. */
    public const string TREE = TenantTree::class;

    /** @var array<string, array{id: string, parent: ?string}> Each tenant placed, by its id, with its parent's, in the order placed. */
    private array $nodes = [];

    /** @var array<string, \Throwable> What asking about each tenant throws, by its id. */
    private array $failures = [];

    /** @var list<array{question: string, tenant: string}> Every question asked, in order. */
    private array $asked = [];

    /**
     * Constructor.
     *
     * @param  ?string  $connection
     */
    public function __construct(

        /** The database connection the subtree is queried on, the default when `null`. */
        private readonly ?string $connection = null,
    ) {}

    /**
     * Bind a fresh fake as the application's tenant tree in the container
     * given, or the application's own, and return it.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @param  ?string  $connection
     * @return self
     */
    public static function fake(?ContainerContract $container = null, ?string $connection = null): self
    {
        $fake = new self($connection);

        ($container ?? Container::getInstance())->instance(self::TREE, $fake);

        return $fake;
    }

    /**
     * Place the tenant under the parent given, or as a root, moving it there
     * when it was placed before; a parent never placed stands as a root.
     *
     * @param  string  $tenantId
     * @param  ?string  $parentId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function place(string $tenantId, ?string $parentId = null): self
    {
        if ($parentId !== null && in_array($tenantId, $this->path($parentId), true)) {
            throw new \InvalidArgumentException(sprintf('Placing the tenant [%s] under [%s] would make a cycle.', $tenantId, $parentId));
        }

        $this->nodes[$tenantId] = ['id' => $tenantId, 'parent' => $parentId];

        return $this;
    }

    /**
     * Remove the tenant, leaving its children under its own parent, or as
     * roots.
     *
     * @param  string  $tenantId
     * @return self
     */
    public function remove(string $tenantId): self
    {
        $parent = $this->nodes[$tenantId]['parent'] ?? null;

        unset($this->nodes[$tenantId]);

        foreach ($this->nodes as $key => $node) {

            if ($node['parent'] !== $tenantId) {
                continue;
            }

            $this->nodes[$key]['parent'] = $parent;
        }

        return $this;
    }

    /**
     * Have every question about the tenant throw, as an application's tree that
     * cannot be read does.
     *
     * @param  string  $tenantId
     * @param  ?\Throwable  $failure
     * @return self
     */
    public function failFor(string $tenantId, ?\Throwable $failure = null): self
    {
        $this->failures[$tenantId] = $failure ?? new \RuntimeException(sprintf('The fake tenant tree cannot be read for the tenant [%s].', $tenantId));

        return $this;
    }

    /**
     * The tenant's ancestors, nearest first, the tenant excluded.
     *
     * @param  string  $tenantId
     * @return list<string>
     *
     * @throws \Throwable
     */
    #[\Override]
    public function ancestors(string $tenantId): array
    {
        $this->ask('ancestors', $tenantId);

        return array_slice($this->path($tenantId), 1);
    }

    /**
     * Every tenant below the tenant, nearest first, in the order placed.
     *
     * @param  string  $tenantId
     * @return list<string>
     *
     * @throws \Throwable
     */
    #[\Override]
    public function descendants(string $tenantId): array
    {
        $this->ask('descendants', $tenantId);

        return $this->below($tenantId);
    }

    /**
     * Whether the tenant is the ancestor given, or below it.
     *
     * @param  string  $tenantId
     * @param  string  $ancestorId
     * @return bool
     *
     * @throws \Throwable
     */
    #[\Override]
    public function isWithin(string $tenantId, string $ancestorId): bool
    {
        $this->ask('isWithin', $tenantId);

        return in_array($ancestorId, $this->path($tenantId), true);
    }

    /**
     * The tenant and every tenant below it, as a query selecting their ids in
     * the `tenant_id` column.
     *
     * @param  string  $tenantId
     * @return \Illuminate\Contracts\Database\Query\Builder
     *
     * @throws \Throwable
     */
    #[\Override]
    public function subtree(string $tenantId): Builder
    {
        $this->ask('subtree', $tenantId);

        $database = Container::getInstance()->make(ConnectionResolverInterface::class)->connection($this->connection);
        $union    = $database->query()->selectRaw('? as ' . self::ID_COLUMN, [$tenantId]);

        foreach ($this->below($tenantId) as $id) {
            $union->unionAll($database->query()->selectRaw('? as ' . self::ID_COLUMN, [$id]));
        }

        return $database->query()->fromSub($union, 'subtree')->select(self::ID_COLUMN);
    }

    /**
     * Every question asked so far, in order: which, and the tenant asked about.
     *
     * @return list<array{question: string, tenant: string}>
     */
    public function asked(): array
    {
        return $this->asked;
    }

    /**
     * Keep the question, and throw what the test told the fake to throw for the
     * tenant.
     *
     * @param  string  $question
     * @param  string  $tenantId
     * @return void
     *
     * @throws \Throwable
     */
    private function ask(string $question, string $tenantId): void
    {
        $this->asked[] = ['question' => $question, 'tenant' => $tenantId];

        if (isset($this->failures[$tenantId])) {
            throw $this->failures[$tenantId];
        }
    }

    /**
     * The tenant, then its ancestors, nearest first.
     *
     * @param  string  $tenantId
     * @return list<string>
     */
    private function path(string $tenantId): array
    {
        $path    = [$tenantId];
        $current = $this->nodes[$tenantId]['parent'] ?? null;

        while ($current !== null) {
            $path[]  = $current;
            $current = $this->nodes[$current]['parent'] ?? null;
        }

        return $path;
    }

    /**
     * Every tenant below the tenant, nearest first, in the order placed.
     *
     * @param  string  $tenantId
     * @return list<string>
     */
    private function below(string $tenantId): array
    {
        $below    = [];
        $frontier = [$tenantId];

        while ($frontier !== []) {

            $next = [];

            foreach ($this->nodes as $node) {
                if ($node['parent'] === null || !in_array($node['parent'], $frontier, true)) {
                    continue;
                }

                $next[] = $node['id'];
            }

            array_push($below, ...$next);

            $frontier = $next;
        }

        return $below;
    }
}
