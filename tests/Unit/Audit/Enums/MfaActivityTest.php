<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Audit\Enums\MfaActivity;

/**
 * Unit tests for the `mfa.*` codes and their definitions (IAM-9.2, IAM-9.3):
 * every code in the `security` category, keeping the application and exactly
 * its properties, a factor by its id and type alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaActivity::class)]
final class MfaActivityTest extends CodesTestCase
{
    /**
     * The enum under test.
     *
     * @return class-string<\SineMacula\Laravel\Iam\Audit\Enums\MfaActivity>
     */
    #[\Override]
    protected static function enum(): string
    {
        return MfaActivity::class;
    }

    /**
     * The reserved prefix its codes are under.
     *
     * @return list<string>
     */
    #[\Override]
    protected static function prefixes(): array
    {
        return ['mfa.'];
    }

    /**
     * Each code, with its category and what it keeps.
     *
     * @return array<string, array{0: string, 1: array<string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling>}>
     */
    #[\Override]
    protected static function expected(): array
    {
        $factor = ['application', 'factor_id', 'factor_type'];

        return [
            'mfa.code_sent'                      => ['security', self::retained(...$factor, ...['purpose'])],
            'mfa.enrollment_started'             => ['security', self::retained(...$factor)],
            'mfa.enrollment_abandoned'           => ['security', self::retained(...$factor)],
            'mfa.enrollment_expired'             => ['security', self::retained(...$factor)],
            'mfa.factor_confirmed'               => ['security', self::retained(...$factor)],
            'mfa.bootstrap_enrollment_completed' => ['security', self::retained(...$factor)],
            'mfa.passkey_associated'             => ['security', self::retained(...$factor)],
            'mfa.factor_disabled'                => ['security', self::retained(...$factor, ...['purpose'])],
            'mfa.factor_enabled'                 => ['security', self::retained(...$factor)],
            'mfa.factor_removed'                 => ['security', self::retained(...$factor)],
            'mfa.factor_renamed'                 => ['security', self::retained(...$factor)],
            'mfa.factors_reset'                  => ['security', self::retained('application', 'reenrollment_required', 'unreadable_factors')],
            'mfa.locked_out'                     => ['security', self::retained(...$factor, ...['purpose', 'locked_until'])],
            'mfa.lockout_lifted'                 => ['security', self::retained(...$factor)],
            'mfa.preferred_factor_changed'       => ['security', self::retained(...$factor, ...['previous_factor_id'])],
            'mfa.recovery_code_used'             => ['security', self::retained('application', 'purpose', 'remaining')],
            'mfa.recovery_codes_low'             => ['security', self::retained('application', 'purpose', 'remaining')],
            'mfa.recovery_codes_generated'       => ['security', self::retained('application', 'count', 'generation')],
            'mfa.recovery_codes_removed'         => ['security', self::retained('application')],
            'mfa.verification_failed'            => ['security', self::retained(...$factor, ...['type', 'purpose'])],
            'mfa.verification_passed'            => ['security', self::retained(...$factor, ...['type', 'purpose'])],
        ];
    }
}
