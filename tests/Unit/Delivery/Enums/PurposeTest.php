<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;

/**
 * Unit tests for what a code is for, in this package's own words: every code
 * purpose of either member has one, `laravel-authentication`'s sign-in code is
 * a first factor and MFA's a further one, and a password reset link is no code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Purpose::class)]
final class PurposeTest extends TestCase
{
    /**
     * The purposes are a sign-in, a verification, a password reset, an
     * identifier change, a further factor and an enrolment, in that order, each
     * backed by its name.
     *
     * @return void
     */
    public function testThePurposesAreTheSixKindsOfCode(): void
    {
        self::assertSame(
            ['sign_in', 'verification', 'password_reset', 'identifier_change', 'additional_factor', 'enrollment'],
            array_column(Purpose::cases(), 'value'),
        );
    }

    /**
     * Rows of `[laravel-authentication's purpose, this package's]` for every
     * code purpose `laravel-authentication` delivers through its sender.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose, 1: \SineMacula\Laravel\Iam\Delivery\Enums\Purpose}>
     */
    public static function provideAuthenticationPurposes(): iterable
    {
        yield 'sign-in' => [CodePurpose::SIGN_IN, Purpose::SIGN_IN];

        yield 'verification' => [CodePurpose::VERIFICATION, Purpose::VERIFICATION];

        yield 'mfa' => [CodePurpose::MFA, Purpose::ADDITIONAL_FACTOR];

        yield 'enrolment' => [CodePurpose::ENROLLMENT, Purpose::ENROLLMENT];

        yield 'password reset' => [CodePurpose::PASSWORD_RESET, Purpose::PASSWORD_RESET];

        yield 'identifier change' => [CodePurpose::CHANGE_IDENTIFIER, Purpose::IDENTIFIER_CHANGE];
    }

    /**
     * Every code purpose of `laravel-authentication`'s is this package's
     * purpose of the same kind; its sign-in code, a first factor, is a sign-in,
     * and its MFA code a further factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Purpose  $expected
     * @return void
     */
    #[DataProvider('provideAuthenticationPurposes')]
    public function testEveryAuthenticationPurposeIsOneOfThisPackages(CodePurpose $purpose, Purpose $expected): void
    {
        self::assertSame($expected, Purpose::fromAuthentication($purpose));
    }

    /**
     * A password reset link is no code, and is refused.
     *
     * @return void
     */
    public function testAPasswordResetLinkIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A password reset link is no code');

        Purpose::fromAuthentication(CodePurpose::PASSWORD_RESET_LINK);
    }

    /**
     * Rows of `[MFA's purpose, this package's]` for every purpose of MFA's.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\Purpose, 1: \SineMacula\Laravel\Iam\Delivery\Enums\Purpose}>
     */
    public static function provideMfaPurposes(): iterable
    {
        yield 'sign-in' => [MfaPurpose::SIGN_IN, Purpose::ADDITIONAL_FACTOR];

        yield 'reauthentication' => [MfaPurpose::REAUTHENTICATE, Purpose::ADDITIONAL_FACTOR];

        yield 'step-up' => [MfaPurpose::STEP_UP, Purpose::ADDITIONAL_FACTOR];

        yield 'enrolment' => [MfaPurpose::ENROLLMENT, Purpose::ENROLLMENT];
    }

    /**
     * Every purpose of MFA's is a further factor, its sign-in included, but an
     * enrolment, which stays one.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Purpose  $expected
     * @return void
     */
    #[DataProvider('provideMfaPurposes')]
    public function testEveryMfaPurposeIsOneOfThisPackages(MfaPurpose $purpose, Purpose $expected): void
    {
        self::assertSame($expected, Purpose::fromMfa($purpose));
    }

    /**
     * The two members' sign-ins are never the same purpose: one is a first
     * factor, the other a further one.
     *
     * @return void
     */
    public function testTheMembersSignInsAreNeverTheSamePurpose(): void
    {
        self::assertNotSame(Purpose::fromAuthentication(CodePurpose::SIGN_IN), Purpose::fromMfa(MfaPurpose::SIGN_IN));
    }
}
