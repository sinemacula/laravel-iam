<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Iam\Contracts\TenantTree;

/**
 * What every application's tenant tree must guarantee, as assertions (IAM-7.5):
 * ancestors answered nearest first, the tenant excluded; no cycles,
 * so every ancestor's own ancestors are the rest of the tenant's; `isWithin()`
 * agreeing with the ancestors, the tenant within itself; descendants agreeing
 * with the ancestors and being exactly the tenants the test case knows are
 * below; and a subtree that is a query of exactly the tenant and those
 * descendants.
 *
 * SSO's enforcement inheritance walks the ancestors nearest first to find the
 * tenant whose rule applies, so a tree answering them in another order would
 * apply a farther rule over a nearer one; and an enforcement change judges the
 * sessions of the enforcing tenant's descendants, so a descendant the tree
 * leaves out keeps sessions the rule no longer allows. So the descendants and
 * the subtree are each checked against the descendants the test case expects,
 * never against the tree's own answer, which could leave out a branch and still
 * agree with itself. Each assertion is handed the tree itself, so a test case
 * asks it as the package asks it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
abstract class TenantTreeContract
{
    /**
     * The tenant's ancestors are exactly those given, nearest first.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\TenantTree  $tree
     * @param  string  $tenantId
     * @param  list<string>  $expected
     * @return void
     */
    public static function assertAncestorsNearestFirst(TenantTree $tree, string $tenantId, array $expected): void
    {
        Assert::assertSame($expected, $tree->ancestors($tenantId), 'The tenant tree did not answer the tenant\'s ancestors nearest first.');
    }

    /**
     * The tenant's ancestors hold neither the tenant nor any tenant twice, and
     * every ancestor's own ancestors are the tenant's beyond it.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\TenantTree  $tree
     * @param  string  $tenantId
     * @return void
     */
    public static function assertNoCycles(TenantTree $tree, string $tenantId): void
    {
        $ancestors = $tree->ancestors($tenantId);

        Assert::assertNotContains($tenantId, $ancestors, 'The tenant tree answered the tenant among its own ancestors.');
        Assert::assertCount(count($ancestors), array_unique($ancestors), 'The tenant tree answered an ancestor twice.');

        foreach ($ancestors as $index => $ancestor) {
            $beyond = array_slice($ancestors, $index + 1);

            Assert::assertSame($beyond, $tree->ancestors($ancestor), 'The tenant tree answered an ancestor\'s ancestors other than the tenant\'s beyond it.');
        }
    }

    /**
     * The tenant is within itself and every ancestor, an ancestor is not within
     * the tenant, and the tenant is not within the outsider given.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\TenantTree  $tree
     * @param  string  $tenantId
     * @param  string  $outsiderId
     * @return void
     */
    public static function assertIsWithinAgreesWithAncestors(TenantTree $tree, string $tenantId, string $outsiderId): void
    {
        Assert::assertTrue($tree->isWithin($tenantId, $tenantId), 'The tenant tree did not answer the tenant within itself.');

        foreach ($tree->ancestors($tenantId) as $ancestor) {
            Assert::assertTrue($tree->isWithin($tenantId, $ancestor), 'The tenant tree did not answer the tenant within one of its ancestors.');
            Assert::assertFalse($tree->isWithin($ancestor, $tenantId), 'The tenant tree answered an ancestor within the tenant.');
        }

        Assert::assertFalse($tree->isWithin($tenantId, $outsiderId), 'The tenant tree answered the tenant within a tenant that is none of its ancestors.');
    }

    /**
     * Every descendant of the tenant is answered once, is not the tenant, and
     * has the tenant among its ancestors, and the descendants answered are
     * exactly those expected, in any order.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\TenantTree  $tree
     * @param  string  $tenantId
     * @param  list<string>  $expected
     * @return void
     */
    public static function assertDescendantsAgreeWithAncestors(TenantTree $tree, string $tenantId, array $expected): void
    {
        $descendants = iterator_to_array($tree->descendants($tenantId), false);

        Assert::assertNotSame([], $descendants, 'The tenant tree answered no descendant of a tenant that has one.');
        Assert::assertNotContains($tenantId, $descendants, 'The tenant tree answered the tenant among its own descendants.');
        Assert::assertCount(count($descendants), array_unique($descendants), 'The tenant tree answered a descendant twice.');

        foreach ($descendants as $descendant) {
            Assert::assertContains($tenantId, $tree->ancestors($descendant), 'The tenant tree answered a descendant the tenant is no ancestor of.');
        }

        sort($descendants);
        sort($expected);

        Assert::assertSame($expected, $descendants, 'The tenant tree left out a descendant of the tenant, or answered one it does not have.');
    }

    /**
     * The subtree is a query selecting, in the `tenant_id` column, exactly the
     * tenant and the descendants expected.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\TenantTree  $tree
     * @param  string  $tenantId
     * @param  list<string>  $descendants
     * @return void
     */
    public static function assertSubtreeIsTheTenantAndItsDescendants(TenantTree $tree, string $tenantId, array $descendants): void
    {
        $selected = array_map(self::selectedIdentifier(...), $tree->subtree($tenantId)->pluck(TenantTree::ID_COLUMN)->all());
        $expected = [$tenantId, ...$descendants];

        sort($selected);
        sort($expected);

        Assert::assertSame($expected, $selected, 'The tenant tree\'s subtree selected other tenants than the tenant and its descendants.');
    }

    /**
     * The identifier a subtree selected, as text: a number, a string, or a
     * value an Eloquent cast made stringable; anything else fails the test
     * case.
     *
     * @param  mixed  $id
     * @return string
     */
    private static function selectedIdentifier(mixed $id): string
    {
        if (!is_int($id) && !is_string($id) && !$id instanceof \Stringable) {
            Assert::fail('The tenant tree\'s subtree selected a tenant by no identifier.');
        }

        return (string) $id;
    }
}
