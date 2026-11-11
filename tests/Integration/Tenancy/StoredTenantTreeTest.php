<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Testing\Concerns\TenantTreeContract;
use Tests\Concerns\MigratesAuthorization;
use Tests\Fixtures\Authorization\Account;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * The tests' application tree, held to `laravel-authorization`'s tenant tree
 * contract with tenants of mixed types.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class StoredTenantTreeTest extends TestCase
{
    use MigratesAuthorization, TenantTreeContract;

    /**
     * The tree under test, its nodes placed.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\TenantTree
     */
    #[\Override]
    protected function tenantTree(): TenantTree
    {
        foreach ($this->tenantTreeNodes() as [$node, $parent]) {
            StoredTenantTree::place($node, $parent);
        }

        return new StoredTenantTree;
    }

    /**
     * An organisation with an account and a team below it, and an organisation
     * apart sharing the account's id.
     *
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null}>
     */
    #[\Override]
    protected function tenantTreeNodes(): array
    {
        $organisation = new Reference(Organisation::TYPE, '1');
        $account      = new Reference(Account::TYPE, '7');

        return [
            [$organisation, null],
            [$account, $organisation],
            [new Reference(Account::TYPE, '8'), $account],
            [new Reference(Organisation::TYPE, '7'), null],
        ];
    }

    /**
     * The tree holds tenants of mixed types.
     *
     * @return bool
     */
    protected function hasMixedTenantTypes(): bool
    {
        return true;
    }
}
