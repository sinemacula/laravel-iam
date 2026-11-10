<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Contracts\GroupResync;
use SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException;

/**
 * Unit tests for the exception a group mapping or re-sync that cannot be built
 * or read throws (IAM-7.2): each names the key or the binding at fault, and
 * never a group, a role, a result or an identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GroupMappingMisconfiguredException::class)]
final class GroupMappingMisconfiguredExceptionTest extends TestCase
{
    /**
     * A class named that is no mapping names the key, the class and the
     * contract.
     *
     * @return void
     */
    public function testAClassNamedThatIsNoMappingNamesTheKey(): void
    {
        $exception = GroupMappingMisconfiguredException::forClass('iam.provisioning.groups.mapping', 'App\Groups\Missing', GroupMapping::class);

        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertSame(
            'iam.provisioning.groups.mapping names [App\Groups\Missing], which is not a class implementing ' . GroupMapping::class . ', so no provider group can be mapped.',
            $exception->getMessage(),
        );
    }

    /**
     * A value that is no class name names the key, the value's type and the
     * contract, never the value.
     *
     * @return void
     */
    public function testAValueThatIsNoClassNameNamesTheKeyAndTheType(): void
    {
        $exception = GroupMappingMisconfiguredException::forValue('iam.provisioning.groups.resync', 'bool', GroupResync::class);

        self::assertSame(
            'iam.provisioning.groups.resync holds a value of type [bool], which names no class implementing ' . GroupResync::class
            . ', so no provider group can be mapped: name the class, or leave it null.',
            $exception->getMessage(),
        );
    }

    /**
     * A binding that resolves to no implementation names the binding, what it
     * resolved to and the contract.
     *
     * @return void
     */
    public function testABindingThatResolvesToNoMappingNamesTheBinding(): void
    {
        $exception = GroupMappingMisconfiguredException::forBinding(GroupMapping::class, \stdClass::class, GroupMapping::class);

        self::assertSame(
            'The container binding of ' . GroupMapping::class . ' resolves to [stdClass], which does not implement ' . GroupMapping::class
            . ', so no provider group can be mapped.',
            $exception->getMessage(),
        );
    }

    /**
     * A map that is no map of groups to roles names the key.
     *
     * @return void
     */
    public function testAMisconfiguredMapNamesTheKey(): void
    {
        self::assertSame(
            'iam.provisioning.groups.map maps each non-empty group name to a role\'s name or a list of them, so no provider group can be mapped.',
            GroupMappingMisconfiguredException::forMap('iam.provisioning.groups.map')->getMessage(),
        );
    }

    /**
     * A re-sync from the mapping with no mapping names the key to name one in.
     *
     * @return void
     */
    public function testAReSyncWithNoMappingNamesTheKey(): void
    {
        self::assertSame(
            'A re-sync from the group mapping needs a mapping: name one in iam.provisioning.groups.mapping, or map groups in its map.',
            GroupMappingMisconfiguredException::forNoMapping('iam.provisioning.groups.mapping')->getMessage(),
        );
    }
}
