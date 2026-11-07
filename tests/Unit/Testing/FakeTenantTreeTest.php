<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Iam\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\TenantTreeTests;
use SineMacula\Laravel\Iam\Testing\Seams\TenantTreeContract;
use Tests\TestCase;

/**
 * Proves the `TenantTree` contract kit against this package's fake tenant tree
 * (IAM-7.5): the fake answers ancestors nearest first, refuses a placement that
 * would make a cycle, answers `isWithin()` and the descendants in agreement
 * with the ancestors, and answers a subtree as a query of the tenant and its
 * descendants; and the kit's assertions fail a tree that breaks any of those.
 * The subtree is queried on the tests' database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeTenantTree::class)]
#[CoversClass(TenantTreeContract::class)]
#[CoversTrait(TenantTreeTests::class)]
final class FakeTenantTreeTest extends TestCase
{
    use TenantTreeTests;

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeTenantTree The fake under test. */
    private ?FakeTenantTree $fake = null;

    /**
     * A tenant never placed has no ancestors and no descendants, is within
     * itself alone, and its subtree is itself; every question is kept.
     *
     * @return void
     */
    public function testATenantNeverPlacedStandsAlone(): void
    {
        $fake = new FakeTenantTree;

        self::assertSame([], $fake->ancestors('stray'));
        self::assertSame([], $fake->descendants('stray'));
        self::assertTrue($fake->isWithin('stray', 'stray'));
        self::assertFalse($fake->isWithin('stray', 'root'));
        self::assertSame(['stray'], array_map(strval(...), $fake->subtree('stray')->pluck(TenantTree::ID_COLUMN)->all()));
        self::assertSame(
            [
                ['question' => 'ancestors', 'tenant' => 'stray'],
                ['question' => 'descendants', 'tenant' => 'stray'],
                ['question' => 'isWithin', 'tenant' => 'stray'],
                ['question' => 'isWithin', 'tenant' => 'stray'],
                ['question' => 'subtree', 'tenant' => 'stray'],
            ],
            $fake->asked(),
        );
    }

    /**
     * Placing a tenant again moves it, with its subtree, and a parent never
     * placed becomes a root.
     *
     * @return void
     */
    public function testPlacingATenantAgainMovesItsSubtree(): void
    {
        $fake = $this->tree()->place('other-root')->place('region', 'other-root');

        self::assertSame(['region', 'other-root'], $fake->ancestors('branch'));
        self::assertSame(['region', 'branch', 'team'], $fake->descendants('other-root'));
        self::assertSame(['region-2'], $fake->descendants('root'));
        self::assertSame(['parent'], (new FakeTenantTree)->place('child', 'parent')->ancestors('child'));
    }

    /**
     * Placing a tenant under itself, or under any tenant below it, is refused.
     *
     * @return void
     */
    public function testAPlacementThatWouldMakeACycleIsRefused(): void
    {
        foreach (['region', 'team'] as $parent) {
            try {
                $this->tree()->place('region', $parent);

                self::fail('A cycle was made.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringContainsString('would make a cycle', $exception->getMessage());
            }
        }

        self::assertSame(['branch', 'region', 'root'], $this->tree()->ancestors('team'));
    }

    /**
     * Removing a tenant leaves its children under its own parent, or as roots.
     *
     * @return void
     */
    public function testRemovingATenantLeavesItsChildrenUnderItsParent(): void
    {
        $fake = $this->tree()->remove('branch');

        self::assertSame(['region', 'root'], $fake->ancestors('team'));
        self::assertSame(['root'], $fake->ancestors('region-2'));

        $fake->remove('root');

        self::assertSame([], $fake->ancestors('region'));
        self::assertSame(['region'], $fake->ancestors('team'));
    }

    /**
     * A tenant the fake was told to fail for throws on every question.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailingTenantThrows(): void
    {
        $failure = new \RuntimeException('Unreadable.');
        $fake    = $this->tree()->failFor('region', $failure)->failFor('team');
        $asks    = [
            static fn (): array => $fake->ancestors('region'),
            static fn (): array => $fake->descendants('region'),
            static fn (): bool => $fake->isWithin('region', 'root'),
            static fn (): Builder => $fake->subtree('region'),
        ];

        foreach ($asks as $ask) {
            try {
                $ask();

                self::fail('The fake answered.');
            } catch (\RuntimeException $exception) {
                self::assertSame($failure, $exception);
            }
        }

        $this->expectException(\RuntimeException::class);

        $fake->ancestors('team');
    }

    /**
     * `fake()` binds a fresh fake as the application's tree, in the container
     * given or the global one, querying the connection it is given.
     *
     * @return void
     */
    public function testFakeBindsAFreshFakeAsTheTree(): void
    {
        $container = new Container;
        $fake      = FakeTenantTree::fake($container, self::CONNECTION);

        self::assertSame($fake, $container->make(TenantTree::class));
        self::assertSame(['solo'], array_map(strval(...), $fake->subtree('solo')->pluck(TenantTree::ID_COLUMN)->all()));

        $other = FakeTenantTree::fake();

        self::assertSame($other, $this->app?->make(FakeTenantTree::TREE));
        self::assertNotSame($fake, $other);
    }

    /**
     * The kit fails a tree that answers the ancestors in another order.
     *
     * @return void
     */
    public function testTheKitFailsAncestorsInAnotherOrder(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('did not answer the tenant\'s ancestors nearest first');

        TenantTreeContract::assertAncestorsNearestFirst($this->tree(), 'team', ['root', 'region', 'branch']);
    }

    /**
     * The kit fails a tree with a cycle, an ancestor answered twice, or an
     * ancestor whose own ancestors disagree.
     *
     * @return void
     */
    public function testTheKitFailsATreeWithACycle(): void
    {
        $cases = [
            'the tenant among its own ancestors' => ['team' => ['branch', 'team']],
            'an ancestor twice'                  => ['team' => ['branch', 'branch']],
            'other than the tenant\'s beyond it' => ['team' => ['branch', 'root'], 'branch' => []],
        ];

        foreach ($cases as $message => $ancestors) {
            try {
                TenantTreeContract::assertNoCycles(self::scripted($ancestors), 'team');

                self::fail('The kit passed.');
            } catch (AssertionFailedError $failure) {
                self::assertStringContainsString($message, $failure->getMessage());
            }
        }
    }

    /**
     * The kit fails a tree whose `isWithin()` disagrees with its ancestors.
     *
     * @return void
     */
    public function testTheKitFailsIsWithinThatDisagrees(): void
    {
        $cases = [
            'within itself'                 => static fn (string $tenant, string $ancestor): bool => $tenant !== $ancestor,
            'within one of its ancestors'   => static fn (string $tenant, string $ancestor): bool => $tenant === $ancestor,
            'an ancestor within the tenant' => static fn (string $tenant, string $ancestor): bool => $ancestor !== 'outsider',
            'none of its ancestors'         => static fn (string $tenant, string $ancestor): bool => $tenant === 'team',
        ];

        foreach ($cases as $message => $isWithin) {
            try {
                TenantTreeContract::assertIsWithinAgreesWithAncestors(self::scripted(['team' => ['branch']], $isWithin), 'team', 'outsider');

                self::fail('The kit passed.');
            } catch (AssertionFailedError $failure) {
                self::assertStringContainsString($message, $failure->getMessage());
            }
        }
    }

    /**
     * The kit fails a tree whose descendants disagree with its ancestors.
     *
     * @return void
     */
    public function testTheKitFailsDescendantsThatDisagree(): void
    {
        $cases = [
            'no descendant'                => [[], ['team']],
            'among its own descendants'    => [['team', 'root'], ['team']],
            'a descendant twice'           => [['team', 'team'], ['team']],
            'the tenant is no ancestor of' => [['stranger'], ['stranger']],
            'left out a descendant'        => [['team'], ['team', 'branch']],
        ];

        foreach ($cases as $message => [$descendants, $expected]) {
            try {
                TenantTreeContract::assertDescendantsAgreeWithAncestors(self::scripted(['team' => ['root'], 'branch' => ['root']], descendants: $descendants), 'root', $expected);

                self::fail('The kit passed.');
            } catch (AssertionFailedError $failure) {
                self::assertStringContainsString($message, $failure->getMessage());
            }
        }
    }

    /**
     * The kit judges every descendant a tree answers lazily, each under the
     * same key, not only the last answered under it.
     *
     * @return void
     */
    public function testTheKitFailsADescendantAnsweredUnderAKeyAnsweredAgain(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('the tenant is no ancestor of');

        $tree = self::scripted(['team' => ['root']], descendants: ['stranger', 'team'], underOneKey: true);

        TenantTreeContract::assertDescendantsAgreeWithAncestors($tree, 'root', ['stranger', 'team']);
    }

    /**
     * The kit fails a tree whose subtree selects other tenants than the tenant
     * and its descendants.
     *
     * @return void
     */
    public function testTheKitFailsASubtreeOfOtherTenants(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('selected other tenants than the tenant and its descendants');

        TenantTreeContract::assertSubtreeIsTheTenantAndItsDescendants(self::scripted([], descendants: ['team'], subtree: ['root']), 'root', ['team']);
    }

    /**
     * The kit fails a tree whose descendants and subtree both leave out the
     * same branch, which agree with each other but not with the tenants below
     * the root.
     *
     * @return void
     */
    public function testTheKitFailsATreeLeavingOutABranch(): void
    {
        $tree = self::scripted(['team' => ['root']], descendants: ['team'], subtree: ['root', 'team']);

        $checks = [
            'left out a descendant'  => static fn () => TenantTreeContract::assertDescendantsAgreeWithAncestors($tree, 'root', ['team', 'branch']),
            'selected other tenants' => static fn () => TenantTreeContract::assertSubtreeIsTheTenantAndItsDescendants($tree, 'root', ['team', 'branch']),
        ];

        foreach ($checks as $message => $check) {
            try {
                $check();

                self::fail('The kit passed.');
            } catch (AssertionFailedError $failure) {
                self::assertStringContainsString($message, $failure->getMessage());
            }
        }
    }

    /**
     * The kit accepts a tree that answers its descendants lazily, under keys of
     * its own, and a subtree selecting numeric ids as numbers.
     *
     * @return void
     */
    public function testTheKitAcceptsLazyDescendantsAndNumericIds(): void
    {
        $tree = new readonly class implements TenantTree {
            /**
             * The root, `1`, above `2` and `3`.
             *
             * @param  string  $tenantId
             * @return list<string>
             */
            #[\Override]
            public function ancestors(string $tenantId): array
            {
                return $tenantId === '1' ? [] : ['1'];
            }

            /**
             * The root's two children, each under the same key.
             *
             * @param  string  $tenantId
             * @return \Generator<int, string>
             */
            #[\Override]
            public function descendants(string $tenantId): \Generator
            {
                yield 0 => '2';

                yield 0 => '3';
            }

            /**
             * Whether the tenant is the ancestor, or below the root.
             *
             * @param  string  $tenantId
             * @param  string  $ancestorId
             * @return bool
             */
            #[\Override]
            public function isWithin(string $tenantId, string $ancestorId): bool
            {
                return $tenantId === $ancestorId || $ancestorId === '1';
            }

            /**
             * The three, selected as numbers.
             *
             * @param  string  $tenantId
             * @return \Illuminate\Contracts\Database\Query\Builder
             */
            #[\Override]
            public function subtree(string $tenantId): Builder
            {
                $database = DB::connection();
                $numbers  = $database->query()->selectRaw('1 as tenant_id');

                foreach ([2, 3] as $number) {
                    $numbers->unionAll($database->query()->selectRaw($number . ' as tenant_id'));
                }

                return $database->query()->fromSub($numbers, 'subtree')->select('tenant_id');
            }
        };

        TenantTreeContract::assertDescendantsAgreeWithAncestors($tree, '1', ['3', '2']);
        TenantTreeContract::assertSubtreeIsTheTenantAndItsDescendants($tree, '1', ['3', '2']);
    }

    /**
     * The fake under test.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\TenantTree
     */
    #[\Override]
    protected function tenantTree(): TenantTree
    {
        return $this->tree();
    }

    /**
     * The leaf, three levels below the root.
     *
     * @return string
     */
    #[\Override]
    protected function treeLeaf(): string
    {
        return 'team';
    }

    /**
     * The leaf's ancestors, nearest first.
     *
     * @return list<string>
     */
    #[\Override]
    protected function treeLeafAncestors(): array
    {
        return ['branch', 'region', 'root'];
    }

    /**
     * A sibling region, none of the leaf's ancestors.
     *
     * @return string
     */
    #[\Override]
    protected function treeOutsider(): string
    {
        return 'region-2';
    }

    /**
     * Every tenant below the root.
     *
     * @return list<string>
     */
    #[\Override]
    protected function treeRootDescendants(): array
    {
        return ['region', 'region-2', 'branch', 'team'];
    }

    /**
     * The fake under test, made once per test: a root with two regions, the
     * first with a branch, the branch with a team.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeTenantTree
     */
    private function tree(): FakeTenantTree
    {
        return $this->fake ??= (new FakeTenantTree)
            ->place('root')
            ->place('region', 'root')
            ->place('region-2', 'root')
            ->place('branch', 'region')
            ->place('team', 'branch');
    }

    /**
     * A tree answering the ancestors, `isWithin()`, the descendants and the
     * subtree given, whatever they are.
     *
     * @param  array<string, list<string>>  $ancestors
     * @param  ?\Closure(string, string): bool  $isWithin
     * @param  list<string>  $descendants
     * @param  list<string>  $subtree
     * @param  bool  $underOneKey
     * @return \SineMacula\Laravel\Iam\Contracts\TenantTree
     */
    private static function scripted(array $ancestors, ?\Closure $isWithin = null, array $descendants = [], array $subtree = [], bool $underOneKey = false): TenantTree
    {
        return new readonly class ($ancestors, $isWithin, $descendants, $subtree, $underOneKey) implements TenantTree {
            /**
             * Constructor.
             *
             * @param  array<string, list<string>>  $ancestors
             * @param  ?\Closure(string, string): bool  $isWithin
             * @param  list<string>  $descendants
             * @param  list<string>  $subtree
             * @param  bool  $underOneKey
             */
            public function __construct(

                /** The ancestors answered, by tenant. */
                private array $ancestors,

                /** What `isWithin()` answers. */
                private ?\Closure $isWithin,

                /** The descendants answered. */
                private array $descendants,

                /** The tenants the subtree selects. */
                private array $subtree,

                /** Whether the descendants are answered lazily, each under the same key. */
                private bool $underOneKey,
            ) {}

            /**
             * The ancestors scripted for the tenant.
             *
             * @param  string  $tenantId
             * @return list<string>
             */
            #[\Override]
            public function ancestors(string $tenantId): array
            {
                return $this->ancestors[$tenantId] ?? [];
            }

            /**
             * The descendants scripted, as a list, or lazily, each under the
             * same key.
             *
             * @param  string  $tenantId
             * @return iterable<string>
             */
            #[\Override]
            public function descendants(string $tenantId): iterable
            {
                return $this->underOneKey ? self::underOneKey($this->descendants) : $this->descendants;
            }

            /**
             * Answer each descendant lazily, under the same key.
             *
             * @param  list<string>  $descendants
             * @return \Generator<int, string>
             */
            private static function underOneKey(array $descendants): \Generator
            {
                foreach ($descendants as $descendant) {
                    yield 0 => $descendant;
                }
            }

            /**
             * What the script answers.
             *
             * @param  string  $tenantId
             * @param  string  $ancestorId
             * @return bool
             */
            #[\Override]
            public function isWithin(string $tenantId, string $ancestorId): bool
            {
                return $this->isWithin === null || ($this->isWithin)($tenantId, $ancestorId);
            }

            /**
             * The tenants scripted, as a query.
             *
             * @param  string  $tenantId
             * @return \Illuminate\Contracts\Database\Query\Builder
             */
            #[\Override]
            public function subtree(string $tenantId): Builder
            {
                $tree = new FakeTenantTree;

                foreach ($this->subtree as $id) {
                    $tree->place($id);
                }

                return $tree->subtree($this->subtree[0] ?? $tenantId);
            }
        };
    }
}
