<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;

/**
 * The identities whose `laravel-authorization` grants are rooted in a tenant's
 * subtree, which a move of that tenant can widen without a grant being written
 * (IAM-6.7, IAM-7.5).
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
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenancyContracts  $contracts
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $tenants
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Lists the tenant's subtree from `laravel-authorization`'s tenant tree. */
        private TenancyContracts $contracts,

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
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
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
     * The grantee of each live grant rooted at the tenant or below it, of
     * whatever type, in every grant table, as its morph type and key.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<array{string, string}>
     *
     * @throws \Throwable
     */
    private function granteesBelow(Reference $tenant): array
    {
        $grantees = [];
        $subtree  = [];

        foreach ($this->contracts->subtree($tenant) as $below) {
            $subtree[$below->type][] = $below->id;
        }

        foreach ($subtree as $type => $ids) {
            foreach (array_chunk($ids, self::CHUNK) as $chunk) {
                foreach (self::TABLES as $table) {
                    $grantees = [...$grantees, ...self::granteesIn($this->tableNamed($table), $type, $chunk)];
                }
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
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private function tableNamed(string $table): string
    {
        return TableNames::get($table, $this->config);
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
