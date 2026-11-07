<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Iam\Contracts\TenantTree;

/**
 * A tenant tree that answers each tenant's descendants lazily, breadth first,
 * from a map of each tenant's children, as a tree reading its store a level at
 * a time would: a cycle in the map below a tenant is answered as it is, again
 * and again, never noticed.
 *
 * So a test is never left waiting on a tree that answers for ever, the answer
 * gives up after a bound and throws `OverflowException`, which a caller that
 * refuses the cycle in time never meets. Only the descendants are asked of it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LazyTenantTree implements TenantTree
{
    /** @var int How many descendants are answered before the answer gives up. */
    public const int BOUND = 1000;

    /**
     * Constructor.
     *
     * @param  array<string, list<string>>  $children
     */
    public function __construct(

        /** Each tenant's children, by the tenant's id. */
        private array $children,
    ) {}

    /**
     * Never asked.
     *
     * @param  string  $tenantId
     * @return list<string>
     *
     * @throws \BadMethodCallException
     */
    #[\Override]
    public function ancestors(string $tenantId): array
    {
        throw new \BadMethodCallException('The lazy tree answers only descendants.');
    }

    /**
     * Every tenant below the tenant, breadth first, as the map gives them, up
     * to the bound.
     *
     * @param  string  $tenantId
     * @return \Generator<int, string>
     *
     * @throws \OverflowException
     */
    #[\Override]
    public function descendants(string $tenantId): \Generator
    {
        $queue    = $this->children[$tenantId] ?? [];
        $answered = 0;

        while ($queue !== []) {

            $descendant = array_shift($queue);

            if (++$answered > self::BOUND) {
                throw new \OverflowException('The lazy tree answered past its bound.');
            }

            yield $descendant;

            array_push($queue, ...$this->children[$descendant] ?? []);
        }
    }

    /**
     * Never asked.
     *
     * @param  string  $tenantId
     * @param  string  $ancestorId
     * @return bool
     *
     * @throws \BadMethodCallException
     */
    #[\Override]
    public function isWithin(string $tenantId, string $ancestorId): bool
    {
        throw new \BadMethodCallException('The lazy tree answers only descendants.');
    }

    /**
     * Never asked.
     *
     * @param  string  $tenantId
     * @return \Illuminate\Contracts\Database\Query\Builder
     *
     * @throws \BadMethodCallException
     */
    #[\Override]
    public function subtree(string $tenantId): Builder
    {
        throw new \BadMethodCallException('The lazy tree answers only descendants.');
    }
}
