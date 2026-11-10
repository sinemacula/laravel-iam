<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;

/**
 * What every group mapping must guarantee, as assertions (IAM-7.2): it answers
 * a list of grant instructions; the same groups map to the same grants every
 * time it is asked; no groups, and groups it does not map, grant nothing; the
 * groups it maps grant what the application expects of them, and nothing
 * else; and a result it declines throws, rather than map its groups to
 * nothing.
 *
 * The provisioning grants whatever the mapping answers, and an opt-in re-sync
 * revokes whatever it no longer answers, so a mapping that answered more than
 * the groups give would grant it, one that answered differently each time would
 * grant and revoke at every sign-in, and one that answered nothing for a result
 * it could not map would revoke every role the groups gave. Each assertion
 * takes the question as a closure, so a test case asks it as the provisioning
 * would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
abstract class GroupMappingContract
{
    /**
     * Asked twice for the same groups, the mapping answers a list of grant
     * instructions, the same both times.
     *
     * @param  \Closure(): array<array-key, mixed>  $ask
     * @return void
     */
    public static function assertAnswersTheSameInstructions(\Closure $ask): void
    {
        $first  = self::instructions($ask);
        $second = self::instructions($ask);

        Assert::assertEquals(self::described($first), self::described($second), 'The group mapping answered different grants for the same groups.');
    }

    /**
     * Asked for groups it does not map, or for none, the mapping grants
     * nothing.
     *
     * @param  \Closure(): array<array-key, mixed>  $ask
     * @return void
     */
    public static function assertGrantsNothing(\Closure $ask): void
    {
        Assert::assertSame([], self::described(self::instructions($ask)), 'The group mapping granted something for groups it does not map.');
    }

    /**
     * Asked for the groups it maps, the mapping grants exactly the roles, with
     * the reach, the application expects, in any order.
     *
     * @param  \Closure(): array<array-key, mixed>  $ask
     * @param  list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>  $expected
     * @return void
     */
    public static function assertGrants(\Closure $ask, array $expected): void
    {
        $answered = self::described(self::instructions($ask));
        $wanted   = self::described($expected);

        sort($answered);
        sort($wanted);

        Assert::assertSame($wanted, $answered, 'The group mapping did not grant exactly what the groups give.');
    }

    /**
     * Asking for a result the mapping declines throws.
     *
     * @param  \Closure(): mixed  $ask
     * @return void
     */
    public static function assertRefusesByThrowing(\Closure $ask): void
    {
        $thrown = null;

        try {
            $ask();
        } catch (\Throwable $exception) {
            $thrown = $exception;
        }

        Assert::assertNotNull($thrown, 'The group mapping answered for a result it declines, rather than throw.');
    }

    /**
     * The answer, asserted to be a list of grant instructions.
     *
     * @param  \Closure(): array<array-key, mixed>  $ask
     * @return list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>
     */
    private static function instructions(\Closure $ask): array
    {
        $answer = $ask();

        Assert::assertTrue(array_is_list($answer), 'The group mapping answered no list.');
        Assert::assertContainsOnlyInstancesOf(GrantInstruction::class, $answer, 'The group mapping answered something that is no grant instruction.');

        /** @var list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction> */
        return $answer;
    }

    /**
     * Each instruction as text naming its role and its reach, which compares by
     * value.
     *
     * @param  list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>  $instructions
     * @return list<string>
     */
    private static function described(array $instructions): array
    {
        return array_map(static fn (GrantInstruction $instruction): string => ($instruction->includeSubtree ? 'subtree ' : 'tenant ') . $instruction->role, $instructions);
    }
}
