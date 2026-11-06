<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Delivery\Enums;

use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;

/**
 * What a code is for, in this package's own words, whichever member issued it,
 * so a gateway words one message per purpose rather than one per member
 * (IAM-3.13).
 *
 * The members spell their purposes differently, and one word means two things:
 * `laravel-authentication`'s `sign_in` is a code that signs a person in on its
 * own, a first factor, while MFA's `sign_in` is a further factor after one. So
 * the first is `sign_in` here, and every further factor, a sign-in's, a
 * step-up's or a reauthentication's, from either member, is
 * `additional_factor`. A gateway that needs the member's finer purpose reads it
 * from the message (`CodeMessage::$memberPurpose`); a code MFA sends through
 * `laravel-authentication` carries only `laravel-authentication`'s `mfa`, which
 * does not tell a sign-in from a step-up.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Purpose: string
{
    // Signing in with the code alone, a first factor (`phone_code`,
    // `email_code`)
    case SIGN_IN = 'sign_in';

    // Verifying an identifier the identity already holds
    case VERIFICATION = 'verification';

    // Resetting a forgotten password
    case PASSWORD_RESET = 'password_reset';

    // Proving a new identifier before it replaces the current one
    case IDENTIFIER_CHANGE = 'identifier_change';

    // A further factor after the first: a sign-in's, a step-up's or a
    // reauthentication's
    case ADDITIONAL_FACTOR = 'additional_factor';

    // Confirming a factor being enrolled
    case ENROLLMENT = 'enrollment';

    /**
     * The purpose of a code `laravel-authentication` issued for the purpose
     * given. A password reset link is no code, and is refused.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromAuthentication(CodePurpose $purpose): self
    {
        return match ($purpose) {
            CodePurpose::SIGN_IN             => self::SIGN_IN,
            CodePurpose::VERIFICATION        => self::VERIFICATION,
            CodePurpose::MFA                 => self::ADDITIONAL_FACTOR,
            CodePurpose::ENROLLMENT          => self::ENROLLMENT,
            CodePurpose::PASSWORD_RESET      => self::PASSWORD_RESET,
            CodePurpose::CHANGE_IDENTIFIER   => self::IDENTIFIER_CHANGE,
            CodePurpose::PASSWORD_RESET_LINK => throw new \InvalidArgumentException('A password reset link is no code: its own sender delivers it.'),
        };
    }

    /**
     * The purpose of a code MFA issued for the purpose given.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return self
     */
    public static function fromMfa(MfaPurpose $purpose): self
    {
        return match ($purpose) {
            MfaPurpose::SIGN_IN, MfaPurpose::REAUTHENTICATE, MfaPurpose::STEP_UP => self::ADDITIONAL_FACTOR,
            MfaPurpose::ENROLLMENT                                               => self::ENROLLMENT,
        };
    }
}
