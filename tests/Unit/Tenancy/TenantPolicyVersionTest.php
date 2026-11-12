<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Iam\Tenancy\TenantPolicyVersion;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;

/**
 * Unit tests for the tenant authentication policy's version.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantPolicyVersion::class)]
final class TenantPolicyVersionTest extends TestCase
{
    /** @var string The tenant every policy here is asked about. */
    private const string TENANT = 'tenant-1';

    /**
     * The same inputs give the same 64-character version.
     *
     * @return void
     */
    public function testTheSameInputsGiveTheSameVersion(): void
    {
        $version = TenantPolicyVersion::of(self::required(), null, self::requirement());

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $version);
        self::assertSame(TenantRequirement::VERSION_MAX_LENGTH, strlen($version));
        self::assertSame($version, TenantPolicyVersion::of(self::required(), null, self::requirement()));
    }

    /**
     * Rows of versions whose inputs differ from the base's in one.
     *
     * @return iterable<string, array{0: \Closure(): string}>
     */
    public static function provideChangedInputs(): iterable
    {
        yield 'the enforcement no longer required' => [static fn (): string => self::versionOf(EnforcementPolicy::notRequired(self::TENANT, self::TENANT, 'enforcement-7'))];

        yield 'another satisfying connection' => [static fn (): string => self::versionOf(self::required(['connection-1', 'connection-3']))];

        yield 'a satisfying connection disabled, the rule unchanged' => [static fn (): string => self::versionOf(self::required(['connection-1']))];

        yield 'another enforcing tenant' => [
            static fn (): string => self::versionOf(EnforcementPolicy::required(self::TENANT, 'tenant-root', ['connection-1', 'connection-2'], 'enforcement-7')),
        ];

        yield 'another rule version' => [static fn (): string => self::versionOf(self::required(version: 'enforcement-8'))];

        yield 'the exemption asked, not exempt' => [static fn (): string => self::versionOf(exemption: ExemptionOutcome::NOT_EXEMPT)];

        yield 'the exemption asked, exempt' => [static fn (): string => self::versionOf(exemption: ExemptionOutcome::EXEMPT)];

        yield 'another maximum age' => [static fn (): string => self::versionOf(requirement: new Requirement(multifactor: new RequirementPart(600)))];

        yield 'any age' => [static fn (): string => self::versionOf(requirement: new Requirement(multifactor: new RequirementPart))];

        yield 'another part' => [static fn (): string => self::versionOf(requirement: new Requirement(additionalVerification: new RequirementPart(300)))];

        yield 'a part added' => [
            static fn (): string => self::versionOf(requirement: new Requirement(multifactor: new RequirementPart(300), phishingResistance: new RequirementPart)),
        ];

        yield 'a minimum level' => [static fn (): string => self::versionOf(requirement: new Requirement(minimumLevel: new LevelRequirement(AssuranceLevel::AAL2)))];

        yield 'nothing required' => [static fn (): string => self::versionOf(requirement: new Requirement)];
    }

    /**
     * A change to any one input gives another version.
     *
     * @param  \Closure(): string  $changed
     * @return void
     */
    #[DataProvider('provideChangedInputs')]
    public function testAChangeToAnyInputGivesAnotherVersion(\Closure $changed): void
    {
        self::assertNotSame(self::versionOf(), $changed());
    }

    /**
     * A minimum level's level and maximum age are each part of the version.
     *
     * @return void
     */
    public function testAMinimumLevelsLevelAndAgeAreEachPartOfTheVersion(): void
    {
        $versions = array_map(
            static fn (LevelRequirement $level): string => TenantPolicyVersion::of(self::required(), null, new Requirement(minimumLevel: $level)),
            [new LevelRequirement(AssuranceLevel::AAL2), new LevelRequirement(AssuranceLevel::AAL3), new LevelRequirement(AssuranceLevel::AAL2, 300)],
        );

        self::assertCount(3, array_unique($versions));
    }

    /**
     * Each part's maximum age is part of the version, whichever part it is.
     *
     * @return void
     */
    public function testEachPartsAgeIsPartOfTheVersion(): void
    {
        $parts = ['additionalVerification', 'multifactor', 'phishingResistance'];

        foreach ($parts as $part) {

            $sooner = self::versionOf(requirement: new Requirement(...[$part => new RequirementPart(60)]));
            $later  = self::versionOf(requirement: new Requirement(...[$part => new RequirementPart(120)]));

            self::assertNotSame($sooner, $later, $part);
        }
    }

    /**
     * The version of the given inputs, each defaulting to the base's.
     *
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome  $exemption
     * @param  ?\SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return string
     *
     * @throws \JsonException
     */
    private static function versionOf(?EnforcementPolicy $policy = null, ?ExemptionOutcome $exemption = null, ?Requirement $requirement = null): string
    {
        return TenantPolicyVersion::of($policy ?? self::required(), $exemption, $requirement ?? self::requirement());
    }

    /**
     * A policy requiring the given connections at the given version.
     *
     * @param  list<string>  $connections
     * @param  string  $version
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     */
    private static function required(array $connections = ['connection-1', 'connection-2'], string $version = 'enforcement-7'): EnforcementPolicy
    {
        return EnforcementPolicy::required(self::TENANT, self::TENANT, $connections, $version);
    }

    /**
     * Multifactor authentication within five minutes.
     *
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    private static function requirement(): Requirement
    {
        return new Requirement(multifactor: new RequirementPart(300));
    }
}
