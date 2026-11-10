<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;

/**
 * The identities whose `laravel-authorization` grants are rooted in a tenant's
 * subtree (IAM-6.7, IAM-7.5): those a move of that tenant can take beyond a
 * tenant they were within, which no grant reports, since none is written.
 *
 * The subtree is the one `laravel-authorization` reads, the application's tree
 * through `TenantTreeAdapter`, read once, as it stands, and every tenant of it
 * resolved through `laravel-authentication`'s tenant resolver
 * (`TenantTreeAdapter::tenantsIn()`): one of another type than the moved
 * tenant's is refused (`TenancyMisconfiguredException`), as a tree that nests
 * tenants of two types is, so the move rolls back rather than report too few of
 * the identities granted below it; one that cannot be resolved throws
 * `UnresolvedReferenceException` (IAM-8.2) the same way. The grants are
 * `laravel-authorization`'s own rows, read on its connection
 * (`authorization.connection`) through its write connection: each live role,
 * permission and policy grant (an expired one holds nowhere) whose tenant is in
 * the subtree, in chunks, so a large subtree never binds more values to one
 * statement than an engine takes. A boundary only ever narrows a scope, so its
 * rows are not read. The tables are those `authorization.tables` names.
 *
 * Each grantee is resolved through the morph map on its own write connection:
 * an identity is itself, and a principal its identity, as
 * `laravel-authentication` names it (`Principal::getIdentity()`). A grantee of
 * any other kind (a role, which `laravel-authorization` says widens nobody's
 * scope) and one whose row is gone hold no identity whose scope the move
 * widens, and are passed over. Each identity is answered once, however many
 * grants it holds there. It takes no lock: it is read inside the move's
 * transaction, and SSO's scope widening, which each identity answered is
 * reported to, takes the locks that matter (`Tenancy\TreeChanges`). Stateless
 * (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubtreeGrantees
{
    /** @var list<string> The grant tables read, each the key `authorization.tables` names it under and its default name. */
    private const array TABLES = ['authorizable_roles', 'authorizable_permissions', 'authorizable_policies'];

    /** @var int How many tenants one statement binds at most. */
    private const int CHUNK = 500;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Authorization\TenantTreeAdapter  $tree
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $tenants
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Lists the tenant's subtree as `laravel-authorization` reads it. */
        private TenantTreeAdapter $tree,

        /** Names the tenant as `laravel-authorization` names it. */
        private TenantTranslator $tenants,

        /** Names each identity found, to answer it once. */
        private IdentityReferences $identities,

        /** Names `laravel-authorization`'s grant tables. */
        private Repository $config,
    ) {}

    /**
     * The identities holding a live grant rooted at the tenant or anywhere
     * below it, each once.
     *
     * @param  string  $tenantId
     * @return list<\SineMacula\Laravel\Authentication\Contracts\Identity>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function of(string $tenantId): array
    {
        $identities = [];

        foreach ($this->granteesBelow($this->tenants->toReference($tenantId)) as [$type, $id]) {

            $identity = self::identityOf($type, $id);

            if ($identity === null) {
                continue;
            }

            $reference = $this->identities->reference($identity);

            $identities[$reference->type . "\0" . $reference->id] = $identity;
        }

        return array_values($identities);
    }

    /**
     * The grantee of each live grant rooted at the tenant or below it, in every
     * grant table, as its morph type and key.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<array{string, string}>
     *
     * @throws \Throwable
     */
    private function granteesBelow(Reference $tenant): array
    {
        $grantees = [];

        $subtree = array_map(static fn (Reference $below): string => $below->id, $this->tree->tenantsIn($tenant));

        foreach (array_chunk($subtree, self::CHUNK) as $chunk) {
            foreach (self::TABLES as $table) {
                $grantees = [...$grantees, ...self::granteesIn($this->tableNamed($table), $tenant->type, $chunk)];
            }
        }

        return $grantees;
    }

    /**
     * The name `authorization.tables` gives the grant table, or its default, as
     * `laravel-authorization` reads it.
     *
     * @param  string  $table
     * @return string
     */
    private function tableNamed(string $table): string
    {
        $named = $this->config->get('authorization.tables.' . $table, $table);

        return is_string($named) ? $named : $table;
    }

    /**
     * The grantee of each live grant in the table rooted at one of the tenants,
     * each once, as its morph type and key.
     *
     * @param  string  $table
     * @param  string  $tenantType
     * @param  array<int, string>  $tenantIds
     * @return array<int, array{string, string}>
     */
    private static function granteesIn(string $table, string $tenantType, array $tenantIds): array
    {
        $query = AuthorizationConnection::connection()->table($table)
            ->useWritePdo()
            ->select(['authorizable_type', 'authorizable_id'])
            ->distinct()
            ->where('tenant_type', $tenantType)
            ->whereIn('tenant_id', $tenantIds);

        LiveGrants::only($query, $table);

        return array_map(static fn (object $row): array => [(string) $row->authorizable_type, (string) $row->authorizable_id], $query->get()->all());
    }

    /**
     * The identity behind the grantee: the identity itself, or a principal's
     * identity; `null` for a grantee that is no model, one of another kind, or
     * one whose row is gone.
     *
     * @param  string  $type
     * @param  string  $id
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function identityOf(string $type, string $id): ?Identity
    {
        $class = Relation::getMorphedModel($type) ?? $type;

        if (!is_a($class, Model::class, true)) {
            return null;
        }

        $blank = new $class;
        $found = WriteConnection::during($blank, static fn (): ?Model => WriteConnection::query($blank->newQuery())->find($id));

        return match (true) {
            $found instanceof Principal => $found->getIdentity(),
            $found instanceof Identity  => $found,
            default                     => null,
        };
    }
}
