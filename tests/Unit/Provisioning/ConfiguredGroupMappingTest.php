<?php

declare(strict_types = 1);

namespace Tests\Unit\Provisioning;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Provisioning\ConfiguredGroupMapping;
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;

/**
 * Unit tests for the group mapping read from configuration (IAM-7.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfiguredGroupMapping::class)]
final class ConfiguredGroupMappingTest extends TestCase
{
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
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('iam.provisioning.groups.map must map each non-empty group name to a role\'s name or a list of them.');

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
     * A group the map does not name, one differing only in case among them, and
     * no group at all, grant nothing.
     *
     * @return void
     */
    public function testUnmappedGroupsGrantNothing(): void
    {
        self::assertSame([], $this->groupMapping()->grantsFor('connection-1', 'tenant-1', ['Finance', 'engineering']));
        self::assertSame([], $this->groupMapping()->grantsFor('connection-1', 'tenant-1', []));
    }

    /**
     * The mapping under test.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\GroupMapping
     */
    private function groupMapping(): GroupMapping
    {
        return new ConfiguredGroupMapping(new Repository(['iam' => ['provisioning' => ['groups' => ['map' => $this->map]]]]));
    }
}
