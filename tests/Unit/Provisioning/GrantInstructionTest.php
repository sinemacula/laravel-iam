<?php

declare(strict_types = 1);

namespace Tests\Unit\Provisioning;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;

/**
 * Unit tests for one grant a provider's groups give.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantInstruction::class)]
final class GrantInstructionTest extends TestCase
{
    /**
     * A role holds in the tenant alone unless it reaches below.
     *
     * @return void
     */
    public function testARoleHoldsInTheTenantAloneUnlessItReachesBelow(): void
    {
        $alone = GrantInstruction::role('invoices.viewer');
        $below = GrantInstruction::roleWithSubtree('invoices.viewer');

        self::assertSame('invoices.viewer', $alone->role);
        self::assertFalse($alone->includeSubtree);
        self::assertSame('invoices.viewer', $below->role);
        self::assertTrue($below->includeSubtree);
        self::assertEquals($alone, new GrantInstruction('invoices.viewer'));
    }

    /**
     * A name of exactly the longest length is accepted.
     *
     * @return void
     */
    public function testTheLongestNameIsAccepted(): void
    {
        $name = str_repeat('r', GrantInstruction::MAX_ROLE_LENGTH);

        self::assertSame($name, GrantInstruction::role($name)->role);
    }

    /**
     * Rows of `[role]`: names no role is named by.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideInvalidRoles(): iterable
    {
        yield 'empty' => [''];

        yield 'blank' => [" \t "];

        yield 'too long' => [str_repeat('r', GrantInstruction::MAX_ROLE_LENGTH + 1)];
    }

    /**
     * A blank name, or one longer than a role's name may be, is refused.
     *
     * @param  string  $role
     * @return void
     */
    #[DataProvider('provideInvalidRoles')]
    public function testAnInvalidNameIsRefused(string $role): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A grant instruction names its role by a non-blank name of at most 191 bytes.');

        GrantInstruction::role($role);
    }
}
