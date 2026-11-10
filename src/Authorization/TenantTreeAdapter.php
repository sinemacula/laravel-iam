<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Query\Grammars\Grammar;
use Illuminate\Database\Query\Grammars\MySqlGrammar;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Contracts\TenantTree as ApplicationTree;
use SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;

/**
 * `laravel-authorization`'s tenant tree, answered from the application's one
 * tenant tree (IAM-7.5, AUTHZ-5.3): the tree this package's own contract
 * (`Contracts\TenantTree`) holds, which SSO's enforcement inheritance and the
 * tree changes read too, so the members never disagree about which tenant is
 * below which.
 *
 * The application's tree names tenants by their opaque ids, and
 * `laravel-authorization` by a `Reference`, a morph type and a key. A tenant's
 * key is its id, as this package names a tenant to `laravel-authorization`
 * everywhere (`Translation\TenantTranslator`), but never on trust: each tenant
 * asked about must resolve back, through `laravel-authentication`'s tenant
 * resolver, to a tenant of its type and key, so a tenant whose key is another
 * tenant's identifier is never read as that other tenant's place in the tree;
 * one that does not throws `UnresolvedReferenceException`.
 *
 * Every tenant of the tree must be of one type, one morph class: the
 * application's subtree query selects only its tenants' ids, so the subtree
 * names each by the type of the tenant asked about, and a tenant below it of
 * another type would be named by the wrong type and match none of its grants. A
 * grant left out of a subtree is no narrower answer: the grant scope query
 * reads it as rooted elsewhere, `outside`, which SSO latches as a suspension.
 * So a tree that places a tenant below one of another type is refused, by
 * `TenancyMisconfiguredException`, wherever this meets it, and a tenant is
 * within an ancestor only when both are of one type:
 *
 * - `ancestors()` answers the tree's ancestors of the tenant, nearest first,
 *   each named as the tenant resolver names its id, and refuses an ancestor of
 *   another type than the tenant's, so a check in a tenant below one of
 *   another type refuses;
 * - `isWithin()` answers the tree's, for two tenants of one type, and `false`
 *   for two of different types, before either is resolved, as `subtree()`
 *   answers;
 * - `tenantsIn()` lists the subtree's tenants, each resolved through the tenant
 *   resolver, and refuses one of another type than the tenant asked about: the
 *   grant half of the principal scope confirms an `outside` answer by it
 *   (`GrantScopeAdapter`), and a move lists its grantees by it
 *   (`SubtreeGrantees`), so neither suspends a link, nor leaves one standing,
 *   on a subtree read by the wrong type;
 * - `subtree()` nests the tree's subtree query, which selects each tenant's id
 *   in its `tenant_id` column, in one of its own on the same connection, which
 *   selects the type of the tenant asked about beside it as `tenant_type`, and
 *   the id as text, cast in the connection's own grammar (`CHAR` on MySQL and
 *   MariaDB, `TEXT` on SQLite, `VARCHAR` on PostgreSQL and elsewhere), as
 *   `laravel-authorization` asks: it compares the subtree's columns with its
 *   own text `tenant_id` columns, which PostgreSQL refuses to do with an
 *   integer column, so a tree whose subtree selects integer ids is read as one
 *   that selects text. It stays on the connection the application's tree
 *   queries: `laravel-authorization` refuses a subtree on another connection
 *   than the scoped models' in `whereAuthorized()`, and its grant scope query
 *   answers `unknown` for one on another connection than
 *   `authorization.connection`, so a tree kept on the storage connection serves
 *   both. It reads no tenant to build the query, so it cannot tell a tenant
 *   below of another type, which `ancestors()` and `tenantsIn()` refuse
 *   instead: every check in such a tenant, every `outside` answer of the grant
 *   half over it and every move of a subtree holding it. A subtree that is no
 *   query builder this can nest is a `LogicException`.
 *
 * It is bound only while the application has a tree (`forApplication()`):
 * `laravel-authorization` tells a flat application by the class of the tree
 * bound (`FlatTenantTree`), never by its answers alone, and takes any other
 * tree down its hierarchical paths, which, in `whereAuthorized()`, nest the
 * subtree query and refuse it on another connection than the scoped model's. So
 * while the application neither names nor binds a tree
 * (`TenancyContracts::hasTree()`), the seam is `laravel-authorization`'s own
 * `FlatTenantTree`, decided as the seam is first resolved in a request or job,
 * and a tree named or bound later is read from the next. Asked with no tree,
 * which only a tree taken away within the request leaves it, it throws
 * `TenancyMisconfiguredException` rather than answer as though every tenant
 * stood alone. The tree is found on every call (`TenancyContracts::tree()`),
 * and whatever it throws propagates, which `laravel-authorization` takes as a
 * tree it cannot read: `unknown` from its grant scope query, and a widening
 * reason of its own for a grant. It reads no request, and keeps nothing between
 * calls (IAM-8.1), yet it is scoped, one for a request or job, as
 * `laravel-authorization`'s own default is: `laravel-authorization` keeps the
 * request's tenant chain only while the tree bound is the very instance it read
 * the chain from (`ResolvedTenant::chain()`), and keys its batch memo of tree
 * reads by the tree instance, so a tree built afresh for each resolution would
 * walk the application's tree, and resolve the tenant and every ancestor
 * through the tenant resolver, again on every check and every tenant-scoped
 * query. The worker reset forgets it with the rest of the request's scoped
 * state.
 *
 * A change to the tree reaches `laravel-authorization`'s caches through the one
 * report the application makes (`Iam::treeChanges()->changed()`, which calls
 * `Authorization::treeChanged()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantTreeAdapter implements TenantTree
{
    /** @var string What a subtree that is no query builder is refused with, naming its class. */
    private const string NOT_A_QUERY = 'The tenant tree answered a subtree of [%s], which is no query builder a query can nest.';

    /** @var string The alias the application's subtree query is nested under. */
    private const string SUBTREE = 'iam_subtree';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenancyContracts  $tenancy
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $tenants
     */
    public function __construct(

        /** Finds the application's tenant tree on every call. */
        private TenancyContracts $tenancy,

        /** Names each tenant by the id the application's tree names it by, and back. */
        private TenantTranslator $tenants,
    ) {}

    /**
     * The tree `laravel-authorization` reads: this adapter while the
     * application names or binds a tree, and `laravel-authorization`'s own
     * `FlatTenantTree` otherwise, which it tells a flat application by.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return \SineMacula\Laravel\Authorization\Contracts\TenantTree
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function forApplication(Container $container): TenantTree
    {
        return TenancyContracts::hasTree($container, $container->make(Repository::class)) ? $container->make(self::class) : new FlatTenantTree;
    }

    /**
     * The tenant's ancestors, nearest first, the tenant itself left out, each
     * of the tenant's type.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    #[\Override]
    public function ancestors(Reference $tenant): array
    {
        return array_map(fn (string $id): Reference => $this->ofType($id, $tenant), $this->tree()->ancestors($this->tenants->idOf($tenant)));
    }

    /**
     * Whether the tenant is the ancestor itself or anywhere below it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function isWithin(Reference $tenant, Reference $ancestor): bool
    {
        return $tenant->type === $ancestor->type && $this->tree()->isWithin($this->tenants->idOf($tenant), $this->tenants->idOf($ancestor));
    }

    /**
     * The tenant and every tenant below it, as a query selecting their
     * `tenant_type` and `tenant_id`.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \LogicException
     * @throws \Throwable
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        $subtree = self::base($this->tree()->subtree($this->tenants->idOf($tenant)));
        $grammar = $subtree->getGrammar();
        $column  = $grammar->wrap(self::SUBTREE . '.' . ApplicationTree::ID_COLUMN);
        $cast    = sprintf('CAST(%s AS %s) as %s', $column, self::textType($grammar), $grammar->wrap(ApplicationTree::ID_COLUMN));

        // The cast is built from this class's constants, quoted by the grammar,
        // so it holds nothing a caller handed in, though it is not a literal
        // string
        return $subtree->newQuery()
            ->fromSub($subtree, self::SUBTREE)
            ->selectRaw('? as tenant_type', [$tenant->type])
            ->selectRaw($cast); // @phpstan-ignore argument.type
    }

    /**
     * The tenant and every tenant below it, each named as the tenant resolver
     * names its id, read from the tree's subtree as it stands, and each of the
     * tenant's type.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function tenantsIn(Reference $tenant): array
    {
        $ids = array_map(static fn (object $row): string => (string) ((array) $row)[ApplicationTree::ID_COLUMN], $this->subtree($tenant)->get()->all());

        return array_values(array_map(fn (string $id): Reference => $this->ofType($id, $tenant), $ids));
    }

    /**
     * The tenant the id names, as the tenant resolver names it, refused when it
     * is of another type than the tenant it was read beside.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $beside
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     */
    private function ofType(string $id, Reference $beside): Reference
    {
        $tenant = $this->tenants->toReference($id);

        return $tenant->type === $beside->type ? $tenant : throw TenancyMisconfiguredException::forMixedTree($tenant->type, $beside->type);
    }

    /**
     * The text type the grammar casts an id to: `CHAR` on MySQL and MariaDB,
     * `TEXT` on SQLite, and `VARCHAR`, which PostgreSQL takes unbounded,
     * elsewhere.
     *
     * @param  \Illuminate\Database\Query\Grammars\Grammar  $grammar
     * @return string
     */
    private static function textType(Grammar $grammar): string
    {
        return match (true) {
            $grammar instanceof MySqlGrammar  => 'CHAR',
            $grammar instanceof SQLiteGrammar => 'TEXT',
            default                           => 'VARCHAR',
        };
    }

    /**
     * The application's tree, which this is bound only beside.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\TenantTree
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     */
    private function tree(): ApplicationTree
    {
        return $this->tenancy->tree() ?? throw TenancyMisconfiguredException::forNone(TenancyContracts::TREE, ApplicationTree::class);
    }

    /**
     * The query builder beneath the application's subtree query, on its own
     * connection.
     *
     * @param  \Illuminate\Contracts\Database\Query\Builder  $subtree
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \LogicException
     */
    private static function base(Builder $subtree): QueryBuilder
    {
        return match (true) {
            $subtree instanceof QueryBuilder                                  => $subtree,
            $subtree instanceof EloquentBuilder, $subtree instanceof Relation => $subtree->toBase(),
            default                                                           => throw new \LogicException(sprintf(self::NOT_A_QUERY, $subtree::class)),
        };
    }
}
