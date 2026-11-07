<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRule;

/**
 * Unit tests for the application's answer for one tenant (IAM-4.5): its version
 * is 1 to 64 characters, the longest a session records, counted as
 * `laravel-authentication` counts them, or none; and a rule that requires
 * nothing is told apart from one that requires something.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantMfaRule::class)]
final class TenantMfaRuleTest extends TestCase
{
    /**
     * Rows of a version a rule carries.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideVersions(): iterable
    {
        yield 'none' => [null];

        yield 'one character' => ['7'];

        yield 'the longest' => [str_repeat('v', TenantRequirement::VERSION_MAX_LENGTH)];

        yield 'the longest, in characters of several bytes' => [str_repeat('é', TenantRequirement::VERSION_MAX_LENGTH)];
    }

    /**
     * A version of 1 to 64 characters, or none, is carried as given, with the
     * requirement.
     *
     * @param  ?string  $version
     * @return void
     */
    #[DataProvider('provideVersions')]
    public function testAVersionWithinItsBoundsIsCarried(?string $version): void
    {
        $requirement = new Requirement(multifactor: new RequirementPart(300));
        $rule        = new TenantMfaRule($requirement, $version);

        self::assertSame($requirement, $rule->requirement);
        self::assertSame($version, $rule->version);
        self::assertSame(TenantRequirement::VERSION_MAX_LENGTH, TenantMfaRule::VERSION_MAX_LENGTH);
    }

    /**
     * Rows of a version no session could record.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideVersionsOutOfBounds(): iterable
    {
        yield 'empty' => [''];

        yield 'one character too long' => [str_repeat('v', TenantRequirement::VERSION_MAX_LENGTH + 1)];

        yield 'one character of several bytes too long' => [str_repeat('é', TenantRequirement::VERSION_MAX_LENGTH + 1)];
    }

    /**
     * An empty version, or one longer than a session records, is refused, as
     * `laravel-authentication` refuses it, so the rule never reaches its
     * policy's answer only to fail there.
     *
     * @param  string  $version
     * @return void
     */
    #[DataProvider('provideVersionsOutOfBounds')]
    public function testAVersionOutOfBoundsIsRefused(string $version): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A tenant MFA rule\'s version must be between 1 and 64 characters.');

        new TenantMfaRule(new Requirement, $version);
    }

    /**
     * A rule that requires nothing is empty, at the version given or none; one
     * that requires a part is not.
     *
     * @return void
     */
    public function testARuleThatRequiresNothingIsEmpty(): void
    {
        self::assertTrue(TenantMfaRule::none()->isEmpty());
        self::assertNull(TenantMfaRule::none()->version);
        self::assertSame('3', TenantMfaRule::none('3')->version);
        self::assertEquals(new Requirement, TenantMfaRule::none()->requirement);
        self::assertFalse(new TenantMfaRule(new Requirement(additionalVerification: new RequirementPart))->isEmpty());
    }
}
