<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams\Concerns;

use SineMacula\Laravel\Iam\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Testing\Seams\TenantTreeContract;

/**
 * The `TenantTree` contract kit (IAM-7.5): the tree answers ancestors nearest
 * first, has no cycles, answers `isWithin()` and the descendants in agreement
 * with the ancestors, and answers a subtree as a query of the tenant and its
 * descendants.
 *
 * A test case proves the application's tree by using this trait and
 * implementing the hooks against its own data: a tenant at least two levels
 * down, its ancestors nearest first, a tenant that is none of them, and every
 * tenant below the farthest ancestor, the root, as the test case's own data
 * holds them. The descendants and the subtree are checked from the root, each
 * against those tenants, so a tree that leaves out a branch fails. The subtree
 * is queried, so a test case runs on a database holding the tree. Each check
 * delegates to `TenantTreeContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait TenantTreeTests
{
    /**
     * The tenant's ancestors are answered nearest first.
     *
     * @return void
     */
    public function testTenantTreeAnswersAncestorsNearestFirst(): void
    {
        TenantTreeContract::assertAncestorsNearestFirst($this->tenantTree(), $this->treeLeaf(), $this->treeLeafAncestors());
    }

    /**
     * The tree has no cycles along the tenant's ancestors.
     *
     * @return void
     */
    public function testTenantTreeHasNoCycles(): void
    {
        TenantTreeContract::assertNoCycles($this->tenantTree(), $this->treeLeaf());
    }

    /**
     * `isWithin()` agrees with the ancestors.
     *
     * @return void
     */
    public function testTenantTreeIsWithinAgreesWithAncestors(): void
    {
        TenantTreeContract::assertIsWithinAgreesWithAncestors($this->tenantTree(), $this->treeLeaf(), $this->treeOutsider());
    }

    /**
     * The root's descendants agree with the ancestors, and are every tenant
     * below it.
     *
     * @return void
     */
    public function testTenantTreeDescendantsAgreeWithAncestors(): void
    {
        TenantTreeContract::assertDescendantsAgreeWithAncestors($this->tenantTree(), $this->treeRoot(), $this->treeRootDescendants());
    }

    /**
     * The root's subtree is a query of the root and every tenant below it.
     *
     * @return void
     */
    public function testTenantTreeSubtreeIsTheTenantAndItsDescendants(): void
    {
        TenantTreeContract::assertSubtreeIsTheTenantAndItsDescendants($this->tenantTree(), $this->treeRoot(), $this->treeRootDescendants());
    }

    /**
     * The tree under test.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\TenantTree
     */
    abstract protected function tenantTree(): TenantTree;

    /**
     * A tenant at least two levels below a root.
     *
     * @return string
     */
    abstract protected function treeLeaf(): string;

    /**
     * The leaf's ancestors, nearest first, the root last.
     *
     * @return list<string>
     */
    abstract protected function treeLeafAncestors(): array;

    /**
     * A tenant that is neither the leaf nor any of its ancestors.
     *
     * @return string
     */
    abstract protected function treeOutsider(): string;

    /**
     * Every tenant below the root, in any order, as the test case's own data
     * holds them.
     *
     * @return list<string>
     */
    abstract protected function treeRootDescendants(): array;

    /**
     * The leaf's farthest ancestor, a root.
     *
     * @return string
     */
    private function treeRoot(): string
    {
        $ancestors = $this->treeLeafAncestors();

        return $ancestors[array_key_last($ancestors)] ?? $this->treeLeaf();
    }
}
