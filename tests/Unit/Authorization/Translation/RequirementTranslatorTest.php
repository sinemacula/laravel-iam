<?php

declare(strict_types = 1);

namespace Tests\Unit\Authorization\Translation;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Iam\Authorization\Translation\RequirementTranslator;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Unit tests for translating `laravel-authorization`'s authentication
 * requirement into MFA's, part for part and age for age, a level MFA does not
 * know refused, and MFA's evaluation back into `laravel-authorization`'s
 * result, the unmet parts named and ordered as `laravel-authorization` names
 * and orders them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementTranslator::class)]
final class RequirementTranslatorTest extends TestCase
{
    /**
     * Rows of `[operand, MFA's requirement]`: each part alone, with and without
     * a maximum age, and every part at once.
     *
     * @return iterable<string, array{0: array<string, array<string, int|string>>, 1: \SineMacula\Laravel\Mfa\Requirements\Requirement}>
     */
    public static function provideRequirements(): iterable
    {
        yield 'additional verification' => [['additional_verification' => []], Requirement::none()->withAdditionalVerification()];

        yield 'multifactor within ten minutes' => [['multifactor' => ['max_age' => 600]], Requirement::none()->withMultifactor(600)];

        yield 'phishing resistance' => [['phishing_resistant' => []], Requirement::none()->withPhishingResistance()];

        yield 'AAL3 within a minute' => [['assurance_level' => ['min' => 'aal3', 'max_age' => 60]], Requirement::none()->withMinimumLevel(AssuranceLevel::AAL3, 60)];

        yield 'every part' => [
            ['assurance_level' => ['min' => 'aal1'], 'phishing_resistant' => ['max_age' => 30], 'multifactor' => [], 'additional_verification' => ['max_age' => 90]],
            Requirement::none()->withAdditionalVerification(90)->withMultifactor()->withPhishingResistance(30)->withMinimumLevel(AssuranceLevel::AAL1),
        ];
    }

    /**
     * Each part crosses as MFA's, with its maximum age.
     *
     * @param  array<string, array<string, int|string>>  $operand
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $expected
     * @return void
     */
    #[DataProvider('provideRequirements')]
    public function testEachPartCrossesWithItsMaximumAge(array $operand, Requirement $expected): void
    {
        self::assertEquals($expected, (new RequirementTranslator)->toMfa(AuthenticationRequirement::fromOperand($operand)));
    }

    /**
     * Rows of `[level]` MFA cannot require.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnknownLevels(): iterable
    {
        yield 'unclassified' => ['unclassified'];

        yield 'another name' => ['gold'];

        yield 'MFA\'s level in another case' => ['AAL2'];
    }

    /**
     * A level MFA cannot require is refused, never read as the nearest.
     *
     * @param  string  $level
     * @return void
     */
    #[DataProvider('provideUnknownLevels')]
    public function testALevelMfaCannotRequireIsRefused(string $level): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('The assurance level [%s] is not one MFA can require: name aal1, aal2 or aal3.', $level));

        (new RequirementTranslator)->toMfa(AuthenticationRequirement::fromOperand(['assurance_level' => ['min' => $level]]));
    }

    /**
     * MFA's evaluation crosses back: met, until the instant it stops being met
     * or unbounded, or unmet, the parts named and ordered as
     * `laravel-authorization` names and orders them.
     *
     * @return void
     */
    public function testTheEvaluationCrossesBack(): void
    {
        $until = CarbonImmutable::parse('2026-11-08 12:00:00');
        $met   = new Evaluation(true, true, AssuranceLevel::AAL2, false, false, ['mfa'], [RequirementPart::MULTIFACTOR], [], $until);
        $open  = new Evaluation(true, true, AssuranceLevel::AAL2, false, false, ['mfa'], [RequirementPart::MULTIFACTOR], []);
        $parts = [RequirementPart::MINIMUM_LEVEL, RequirementPart::PHISHING_RESISTANCE, RequirementPart::MULTIFACTOR];
        $unmet = new Evaluation(true, false, AssuranceLevel::AAL1, false, false, [], [RequirementPart::ADDITIONAL_VERIFICATION], $parts);

        $translator = new RequirementTranslator;

        self::assertTrue($translator->result($met)->isMet);
        self::assertEquals($until, $translator->result($met)->metUntil);
        self::assertTrue($translator->result($open)->isMet);
        self::assertNull($translator->result($open)->metUntil);
        self::assertFalse($translator->result($unmet)->isMet);
        self::assertSame(['multifactor', 'phishing_resistant', 'assurance_level'], $translator->result($unmet)->unmet);
    }
}
