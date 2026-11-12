<?php

declare(strict_types = 1);

namespace Tests\Unit\Mfa\Translation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel as AuthenticationLevel;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement as AuthenticationRequirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart as AuthenticationRequirementPart;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel as MfaLevel;
use SineMacula\Laravel\Mfa\Enums\RequirementPart as MfaRequirementPart;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;

/**
 * Unit tests for translating requirements and assurance levels.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementTranslator::class)]
final class RequirementTranslatorTest extends TestCase
{
    /** @var string The refusal of a minimum assurance level asked as freshness. */
    private const string NO_MINIMUM_LEVEL = 'laravel-authentication\'s freshness cannot hold a session to a minimum assurance level, which its proofs do not record:'
        . ' configure the operation\'s freshness without one, or bind a gate of your own that judges it.';

    /**
     * Rows of `[laravel-authentication's requirement, MFA's]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Requirements\Requirement, 1: \SineMacula\Laravel\Mfa\Requirements\Requirement}>
     */
    public static function provideRequirements(): iterable
    {
        yield 'nothing' => [new AuthenticationRequirement, MfaRequirement::none()];

        yield 'additional verification' => [
            new AuthenticationRequirement(additionalVerification: new AuthenticationRequirementPart(300)),
            MfaRequirement::none()->withAdditionalVerification(300),
        ];

        yield 'multifactor' => [
            new AuthenticationRequirement(multifactor: new AuthenticationRequirementPart),
            MfaRequirement::none()->withMultifactor(),
        ];

        yield 'minimum level' => [
            new AuthenticationRequirement(minimumLevel: new LevelRequirement(AuthenticationLevel::AAL2, 600)),
            MfaRequirement::none()->withMinimumLevel(MfaLevel::AAL2, 600),
        ];

        yield 'minimum level of any age' => [
            new AuthenticationRequirement(minimumLevel: new LevelRequirement(AuthenticationLevel::AAL3)),
            MfaRequirement::none()->withMinimumLevel(MfaLevel::AAL3),
        ];

        yield 'phishing resistance' => [
            new AuthenticationRequirement(phishingResistance: new AuthenticationRequirementPart(900)),
            MfaRequirement::none()->withPhishingResistance(900),
        ];

        yield 'every part' => [
            new AuthenticationRequirement(
                new AuthenticationRequirementPart(60),
                new AuthenticationRequirementPart(120),
                new LevelRequirement(AuthenticationLevel::AAL1, 180),
                new AuthenticationRequirementPart(240),
            ),
            MfaRequirement::none()->withAdditionalVerification(60)->withMultifactor(120)->withMinimumLevel(MfaLevel::AAL1, 180)->withPhishingResistance(240),
        ];
    }

    /**
     * A requirement crosses to MFA's with the same parts, ages and level.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $authentication
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $mfa
     * @return void
     */
    #[DataProvider('provideRequirements')]
    public function testARequirementIsMfasWithTheSameParts(AuthenticationRequirement $authentication, MfaRequirement $mfa): void
    {
        self::assertSame($mfa->toArray(), (new RequirementTranslator)->toMfa($authentication)->toArray());
    }

    /**
     * MFA's requirement crosses back with the same parts, ages and level.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $authentication
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $mfa
     * @return void
     */
    #[DataProvider('provideRequirements')]
    public function testARequirementIsLaravelAuthenticationsWithTheSameParts(AuthenticationRequirement $authentication, MfaRequirement $mfa): void
    {
        self::assertEquals($authentication, (new RequirementTranslator)->toAuthentication($mfa));
    }

    /**
     * A maximum age over a year is refused rather than shortened.
     *
     * @return void
     */
    public function testAMaximumAgeLaravelAuthenticationRefusesIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new RequirementTranslator)->toAuthentication(MfaRequirement::none()->withMultifactor(AuthenticationRequirementPart::MAX_AGE_SECONDS + 1));
    }

    /**
     * Rows of `[MFA's level, laravel-authentication's]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\AssuranceLevel, 1: ?\SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel}>
     */
    public static function provideLevels(): iterable
    {
        yield 'aal1' => [MfaLevel::AAL1, AuthenticationLevel::AAL1];

        yield 'aal2' => [MfaLevel::AAL2, AuthenticationLevel::AAL2];

        yield 'aal3' => [MfaLevel::AAL3, AuthenticationLevel::AAL3];

        yield 'unclassified' => [MfaLevel::UNCLASSIFIED, null];
    }

    /**
     * Every level crosses as itself, and MFA's `unclassified` is no level.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $mfa
     * @param  ?\SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel  $authentication
     * @return void
     */
    #[DataProvider('provideLevels')]
    public function testEveryLevelCrossesAsItselfAndUnclassifiedIsNone(MfaLevel $mfa, ?AuthenticationLevel $authentication): void
    {
        $translator = new RequirementTranslator;

        self::assertSame($authentication, $translator->level($mfa));

        if ($authentication === null) {
            return;
        }

        self::assertSame($mfa, $translator->toMfaLevel($authentication));
    }

    /**
     * Rows of `[MFA's part, laravel-authentication's kind]` for every part.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\RequirementPart, 1: \SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind}>
     */
    public static function provideParts(): iterable
    {
        yield 'additional verification' => [MfaRequirementPart::ADDITIONAL_VERIFICATION, RequirementKind::ADDITIONAL_VERIFICATION];

        yield 'multifactor' => [MfaRequirementPart::MULTIFACTOR, RequirementKind::MULTIFACTOR];

        yield 'minimum level' => [MfaRequirementPart::MINIMUM_LEVEL, RequirementKind::MINIMUM_LEVEL];

        yield 'phishing resistance' => [MfaRequirementPart::PHISHING_RESISTANCE, RequirementKind::PHISHING_RESISTANCE];
    }

    /**
     * Every part crosses as itself, both ways.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @param  \SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind  $kind
     * @return void
     */
    #[DataProvider('provideParts')]
    public function testEveryPartCrossesAsItself(MfaRequirementPart $part, RequirementKind $kind): void
    {
        $translator = new RequirementTranslator;

        self::assertSame($kind, $translator->kind($part));
        self::assertSame($part, $translator->part($kind));
    }

    /**
     * MFA's evaluation leaves the same parts unmet, in order.
     *
     * @return void
     */
    public function testAnEvaluationLeavesTheSamePartsUnmet(): void
    {
        $translator = new RequirementTranslator;

        $met   = [MfaRequirementPart::ADDITIONAL_VERIFICATION];
        $unmet = new Evaluation(true, false, MfaLevel::AAL1, false, false, [], $met, [MfaRequirementPart::PHISHING_RESISTANCE, MfaRequirementPart::MULTIFACTOR]);
        $all   = new Evaluation(true, true, MfaLevel::AAL2, false, false, ['mfa'], [MfaRequirementPart::MULTIFACTOR], []);

        self::assertSame([RequirementKind::PHISHING_RESISTANCE, RequirementKind::MULTIFACTOR], $translator->evaluation($unmet)->unmet);
        self::assertTrue($translator->evaluation($all)->isMet());
    }

    /**
     * Rows of `[MFA's requirement, the freshness requirement for each part]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Requirements\Requirement, 1: list<\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement>}>
     */
    public static function provideFreshnessParts(): iterable
    {
        $additional = [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE];

        yield 'nothing' => [MfaRequirement::none(), []];

        yield 'additional verification' => [MfaRequirement::none()->withAdditionalVerification(300), [new FreshnessRequirement(300, $additional)]];

        yield 'multifactor' => [MfaRequirement::none()->withMultifactor(60), [new FreshnessRequirement(60, ProofKind::cases(), multifactor: true)]];

        yield 'phishing resistance' => [MfaRequirement::none()->withPhishingResistance(86400), [new FreshnessRequirement(86400, ProofKind::cases(), phishingResistant: true)]];

        yield 'every part but a level' => [
            MfaRequirement::none()->withPhishingResistance(900)->withAdditionalVerification(300)->withMultifactor(600),
            [
                new FreshnessRequirement(300, $additional),
                new FreshnessRequirement(600, ProofKind::cases(), multifactor: true),
                new FreshnessRequirement(900, ProofKind::cases(), phishingResistant: true),
            ],
        ];
    }

    /**
     * Each part is a freshness requirement of its own, within its age.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  list<\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement>  $parts
     * @return void
     */
    #[DataProvider('provideFreshnessParts')]
    public function testEachPartIsAFreshnessRequirementOfItsOwn(MfaRequirement $requirement, array $parts): void
    {
        self::assertEquals($parts, (new RequirementTranslator)->toFreshnessParts($requirement));
    }

    /**
     * Rows of `[MFA's requirement, the refusal message]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Requirements\Requirement, 1: string}>
     */
    public static function provideUnfreshParts(): iterable
    {
        yield 'a minimum level' => [MfaRequirement::none()->withMinimumLevel(MfaLevel::AAL2, 300), self::NO_MINIMUM_LEVEL];

        yield 'a part with no maximum age' => [MfaRequirement::none()->withMultifactor(), 'A freshness requirement\'s [multifactor] part must have a maximum age.'];

        yield 'a part longer than a day' => [MfaRequirement::none()->withAdditionalVerification(86401), 'A freshness requirement\'s maximum age must be from 1 to 86400 seconds.'];
    }

    /**
     * A part no freshness requirement can hold is refused.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideUnfreshParts')]
    public function testAPartNoFreshnessCanHoldIsRefused(MfaRequirement $requirement, string $message): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException($message));

        (new RequirementTranslator)->toFreshnessParts($requirement);
    }

    /**
     * Rows of `[MFA's requirement, the one freshness requirement holding it]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Requirements\Requirement, 1: ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement}>
     */
    public static function provideFreshness(): iterable
    {
        $additional = [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE];

        yield 'nothing' => [MfaRequirement::none(), null];

        yield 'additional verification' => [MfaRequirement::none()->withAdditionalVerification(300), new FreshnessRequirement(300, $additional)];

        yield 'multifactor' => [MfaRequirement::none()->withMultifactor(600), new FreshnessRequirement(600, ProofKind::cases(), true)];

        yield 'phishing resistance' => [MfaRequirement::none()->withPhishingResistance(900), new FreshnessRequirement(900, ProofKind::cases(), false, true)];

        yield 'no maximum age' => [MfaRequirement::none()->withMultifactor(), new FreshnessRequirement(86400, ProofKind::cases(), true)];

        yield 'longer than a day' => [MfaRequirement::none()->withPhishingResistance(172800), new FreshnessRequirement(86400, ProofKind::cases(), false, true)];

        yield 'every part but a level' => [
            MfaRequirement::none()->withPhishingResistance(900)->withMultifactor()->withAdditionalVerification(600),
            new FreshnessRequirement(600, $additional, true, true),
        ];
    }

    /**
     * A whole requirement is one freshness requirement at the shortest age.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $freshness
     * @return void
     */
    #[DataProvider('provideFreshness')]
    public function testARequirementAskedAsAWholeIsOneFreshnessRequirement(MfaRequirement $requirement, ?FreshnessRequirement $freshness): void
    {
        self::assertEquals($freshness, (new RequirementTranslator)->toFreshness($requirement));
    }

    /**
     * A minimum level asked as a whole is refused, as asked part by part.
     *
     * @return void
     */
    public function testAMinimumLevelAskedAsAWholeIsRefused(): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException(self::NO_MINIMUM_LEVEL));

        (new RequirementTranslator)->toFreshness(MfaRequirement::none()->withAdditionalVerification(60)->withMinimumLevel(MfaLevel::AAL1, 60));
    }

    /**
     * Rows of `[freshness requirement, the MFA parts it expresses]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement, 1: ?\SineMacula\Laravel\Mfa\Requirements\Requirement}>
     */
    public static function provideFreshnessSettings(): iterable
    {
        yield 'further factors and recovery codes' => [
            new FreshnessRequirement(300, [ProofKind::RECOVERY_CODE, ProofKind::ADDITIONAL_FACTOR]),
            MfaRequirement::none()->withAdditionalVerification(300),
        ];

        yield 'further factors alone' => [new FreshnessRequirement(120, [ProofKind::ADDITIONAL_FACTOR]), MfaRequirement::none()->withAdditionalVerification(120)];

        yield 'a first factor' => [new FreshnessRequirement(900, [ProofKind::FIRST_FACTOR_REAUTHENTICATION, ProofKind::ADDITIONAL_FACTOR]), null];

        yield 'every kind, multifactor' => [new FreshnessRequirement(600, ProofKind::cases(), true), MfaRequirement::none()->withMultifactor(600)];

        yield 'every kind, resisting phishing' => [new FreshnessRequirement(60, ProofKind::cases(), false, true), MfaRequirement::none()->withPhishingResistance(60)];

        yield 'further factors, both flags' => [
            new FreshnessRequirement(30, [ProofKind::ADDITIONAL_FACTOR], true, true),
            MfaRequirement::none()->withAdditionalVerification(30)->withMultifactor(30)->withPhishingResistance(30),
        ];
    }

    /**
     * A freshness requirement is MFA's for the parts it expresses, or none.
     *
     * @param  \SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $freshness
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return void
     */
    #[DataProvider('provideFreshnessSettings')]
    public function testAFreshnessRequirementIsMfasForThePartsItExpresses(FreshnessRequirement $freshness, ?MfaRequirement $requirement): void
    {
        self::assertSame($requirement?->toArray(), (new RequirementTranslator)->fromFreshness($freshness)?->toArray());
    }
}
