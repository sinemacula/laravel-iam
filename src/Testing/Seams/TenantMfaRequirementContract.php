<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRule;

/**
 * What every tenant MFA requirement must guarantee, as assertions (IAM-4.5): it
 * answers a tenant the same way every time it is asked while nothing changes,
 * version included; a changed answer comes with a changed version (or none,
 * which is never taken as already checked); and a tenant it cannot answer for
 * throws, rather than answer that nothing is required.
 *
 * `laravel-authentication` skips a session recorded at the very version its
 * tenant policy answers, so a requirement whose version stayed the same while
 * its answer changed would leave sessions standing that no longer meet it, and
 * one whose version changed for nothing would judge every session again. Each
 * assertion takes the question as a closure, so a test case asks it as the
 * application's own requirement would be asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
abstract class TenantMfaRequirementContract
{
    /**
     * Asking about the tenant twice, with nothing changed in between, answers
     * the same requirement at the same version.
     *
     * @param  \Closure(): \SineMacula\Laravel\Iam\Tenancy\TenantMfaRule  $ask
     * @return void
     */
    public static function assertDeterministic(\Closure $ask): void
    {
        $first  = $ask();
        $second = $ask();

        Assert::assertEquals($first->requirement, $second->requirement, 'The tenant MFA requirement answered the same tenant differently with nothing changed.');
        Assert::assertSame($first->version, $second->version, 'The tenant MFA requirement answered the same tenant at another version with nothing changed.');
    }

    /**
     * Once the tenant's requirement is changed, its answer is another, at
     * another version, or at none.
     *
     * @param  \Closure(): \SineMacula\Laravel\Iam\Tenancy\TenantMfaRule  $ask
     * @param  \Closure(): void  $change
     * @return void
     */
    public static function assertVersionChangesWithTheAnswer(\Closure $ask, \Closure $change): void
    {
        $before = $ask();

        $change();

        $after = $ask();

        Assert::assertNotEquals($before->requirement, $after->requirement, 'The change made to the tenant\'s requirement did not change what it answers.');
        Assert::assertTrue(self::isAnotherVersion($before, $after), 'The tenant MFA requirement answered a changed requirement at the version it answered before.');
    }

    /**
     * Asking about a tenant the requirement cannot answer for throws.
     *
     * @param  \Closure(): \SineMacula\Laravel\Iam\Tenancy\TenantMfaRule  $ask
     * @return void
     */
    public static function assertThrowsRatherThanAnswersNothing(\Closure $ask): void
    {
        $thrown = null;

        try {
            $ask();
        } catch (\Throwable $exception) {
            $thrown = $exception;
        }

        Assert::assertNotNull($thrown, 'The tenant MFA requirement answered for a tenant it cannot answer for, rather than throw.');
    }

    /**
     * Whether the answer after a change is at another version than before, or
     * at none.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenantMfaRule  $before
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenantMfaRule  $after
     * @return bool
     */
    private static function isAnotherVersion(TenantMfaRule $before, TenantMfaRule $after): bool
    {
        return $after->version === null || $after->version !== $before->version;
    }
}
