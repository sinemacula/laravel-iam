<?php

declare(strict_types = 1);

namespace Tests\Unit\Provisioning;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException;
use SineMacula\Laravel\Iam\Provisioning\ConfiguredGroupMapping;
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;
use SineMacula\Laravel\Iam\Provisioning\GroupSettings;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\GroupMappingTests;
use SineMacula\Laravel\Iam\Testing\Seams\GroupMappingContract;

/**
 * Unit tests for the group mapping read from configuration (IAM-7.2), proved
 * against this package's own contract kit: each group maps to the roles the map
 * names, a role two groups name is granted once, a group the map does not name,
 * and no group, grant nothing, every role holds in the connection's tenant
 * alone, and a map that is no map of group names to role names throws rather
 * than map the groups to nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfiguredGroupMapping::class)]
#[CoversClass(GroupMappingContract::class)]
final class ConfiguredGroupMappingTest extends TestCase
{
    use GroupMappingTests;

    /** @var array<array-key, mixed> The map the configuration holds. */
    private array $map = [
        'finance'     => 'invoices.viewer',
        'finance-ops' => ['invoices.viewer', 'invoices.approver'],
        '42'          => 'numbered',
    ];

    /**
     * A role two groups name is granted once, in the order the groups first
     * name it, and a group named by a number is matched by its text.
     *
     * @return void
     */
    public function testEachRoleIsGrantedOnceInOrder(): void
    {
        $grants = $this->groupMapping()->grantsFor('connection-1', 'tenant-1', ['finance-ops', 'finance', '42']);

        self::assertEquals([GrantInstruction::role('invoices.viewer'), GrantInstruction::role('invoices.approver'), GrantInstruction::role('numbered')], $grants);
    }

    /**
     * Rows of `[map]`: values that are no map of group names to role names.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMisconfiguredMaps(): iterable
    {
        yield 'no array' => ['finance'];

        yield 'a list rather than a map' => [['invoices.viewer']];

        yield 'an empty group name' => [['' => 'invoices.viewer']];

        yield 'a role that is no text' => [['finance' => 7]];

        yield 'a blank role' => [['finance' => ' ']];

        yield 'roles keyed by name' => [['finance' => ['first' => 'invoices.viewer']]];

        yield 'a role list holding no text' => [['finance' => ['invoices.viewer', null]]];
    }

    /**
     * A map that is no map of group names to role names throws, naming the key.
     *
     * @param  mixed  $map
     * @return void
     */
    #[DataProvider('provideMisconfiguredMaps')]
    public function testAMisconfiguredMapThrows(mixed $map): void
    {
        $this->expectException(GroupMappingMisconfiguredException::class);
        $this->expectExceptionMessage(GroupSettings::MAP);

        (new ConfiguredGroupMapping(new Repository(['iam' => ['provisioning' => ['groups' => ['map' => $map]]]])))->grantsFor('connection-1', 'tenant-1', ['finance']);
    }

    /**
     * An empty map maps every group to nothing.
     *
     * @return void
     */
    public function testAnEmptyMapGrantsNothing(): void
    {
        $this->map = [];

        self::assertSame([], $this->groupMapping()->grantsFor('connection-1', 'tenant-1', ['finance']));
    }

    /**
     * The mapping under test.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\GroupMapping
     */
    #[\Override]
    protected function groupMapping(): GroupMapping
    {
        return new ConfiguredGroupMapping(new Repository(['iam' => ['provisioning' => ['groups' => ['map' => $this->map]]]]));
    }

    /**
     * The connection the groups are reported through.
     *
     * @return string
     */
    #[\Override]
    protected function connectionId(): string
    {
        return 'connection-1';
    }

    /**
     * The connection's tenant.
     *
     * @return string
     */
    #[\Override]
    protected function tenantId(): string
    {
        return 'tenant-1';
    }

    /**
     * Groups the map names.
     *
     * @return list<string>
     */
    #[\Override]
    protected function mappedGroups(): array
    {
        return ['finance', 'finance-ops'];
    }

    /**
     * Groups the map does not name, one differing from a mapped one only in
     * case.
     *
     * @return list<string>
     */
    #[\Override]
    protected function unmappedGroups(): array
    {
        return ['Finance', 'engineering'];
    }

    /**
     * The roles the mapped groups give.
     *
     * @return list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>
     */
    #[\Override]
    protected function expectedGrants(): array
    {
        return [GrantInstruction::role('invoices.viewer'), GrantInstruction::role('invoices.approver')];
    }

    /**
     * A question asked of a misconfigured map.
     *
     * @return \Closure(): mixed
     */
    #[\Override]
    protected function declinedQuestion(): \Closure
    {
        $mapping = new ConfiguredGroupMapping(new Repository(['iam' => ['provisioning' => ['groups' => ['map' => 'finance']]]]));

        return static fn (): array => $mapping->grantsFor('connection-1', 'tenant-1', ['finance']);
    }
}
