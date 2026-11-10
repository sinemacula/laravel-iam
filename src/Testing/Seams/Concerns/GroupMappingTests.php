<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams\Concerns;

use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Testing\Seams\GroupMappingContract;

/**
 * The `GroupMapping` contract kit (IAM-7.2): the mapping answers the same grant
 * instructions for the same groups every time, grants nothing for no groups and
 * for groups it does not map, grants exactly what the groups it maps give, and
 * throws for a result it declines.
 *
 * A test case proves the application's mapping by using this trait and
 * implementing the hooks against its own configuration: a connection and its
 * tenant, groups it maps and the grants they give, groups it does not map, and
 * a question it declines, if it declines any. Each check delegates to
 * `GroupMappingContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait GroupMappingTests
{
    /**
     * The mapping answers the same grants for the same groups every time.
     *
     * @return void
     */
    public function testGroupMappingAnswersTheSameGrantsEachTime(): void
    {
        $mapping = $this->groupMapping();
        $groups  = $this->mappedGroups();

        GroupMappingContract::assertAnswersTheSameInstructions(fn (): array => $mapping->grantsFor($this->connectionId(), $this->tenantId(), $groups));
    }

    /**
     * No groups grant nothing.
     *
     * @return void
     */
    public function testGroupMappingGrantsNothingForNoGroups(): void
    {
        $mapping = $this->groupMapping();

        GroupMappingContract::assertGrantsNothing(fn (): array => $mapping->grantsFor($this->connectionId(), $this->tenantId(), []));
    }

    /**
     * Groups the mapping does not map grant nothing.
     *
     * @return void
     */
    public function testGroupMappingGrantsNothingForGroupsItDoesNotMap(): void
    {
        $mapping = $this->groupMapping();
        $groups  = $this->unmappedGroups();

        GroupMappingContract::assertGrantsNothing(fn (): array => $mapping->grantsFor($this->connectionId(), $this->tenantId(), $groups));
    }

    /**
     * The groups the mapping maps grant exactly what the application expects,
     * with the groups it does not map among them changing nothing.
     *
     * @return void
     */
    public function testGroupMappingGrantsExactlyWhatTheGroupsGive(): void
    {
        $mapping = $this->groupMapping();
        $groups  = [...$this->mappedGroups(), ...$this->unmappedGroups()];

        GroupMappingContract::assertGrants(fn (): array => $mapping->grantsFor($this->connectionId(), $this->tenantId(), $groups), $this->expectedGrants());
    }

    /**
     * A question the mapping declines throws, rather than map to nothing; a
     * mapping that declines nothing passes.
     *
     * @return void
     */
    public function testGroupMappingRefusesByThrowing(): void
    {
        $declined = $this->declinedQuestion();

        if ($declined === null) {
            $this->addToAssertionCount(1);

            return;
        }

        GroupMappingContract::assertRefusesByThrowing($declined);
    }

    /**
     * The mapping under test.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\GroupMapping
     */
    abstract protected function groupMapping(): GroupMapping;

    /**
     * The connection the groups are reported through.
     *
     * @return string
     */
    abstract protected function connectionId(): string;

    /**
     * The connection's tenant.
     *
     * @return string
     */
    abstract protected function tenantId(): string;

    /**
     * Groups the mapping maps to something, through the connection.
     *
     * @return list<string>
     */
    abstract protected function mappedGroups(): array;

    /**
     * Groups the mapping maps to nothing, through the connection.
     *
     * @return list<string>
     */
    abstract protected function unmappedGroups(): array;

    /**
     * The grants the mapped groups give, together.
     *
     * @return list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>
     */
    abstract protected function expectedGrants(): array;

    /**
     * A question the mapping declines, asked of it, or `null` when it declines
     * none.
     *
     * @return ?\Closure(): mixed
     */
    abstract protected function declinedQuestion(): ?\Closure;
}
