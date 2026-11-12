<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Enums;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\Iam\Audit\Contracts\ListsProperties;

/**
 * The `mfa.*` codes MFA's events are recorded under, one per event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
enum MfaActivity: string implements ListsProperties
{
    case CODE_SENT            = 'mfa.code_sent';
    case ENROLLMENT_STARTED   = 'mfa.enrollment_started';
    case ENROLLMENT_ABANDONED = 'mfa.enrollment_abandoned';
    case ENROLLMENT_EXPIRED   = 'mfa.enrollment_expired';
    case FACTOR_CONFIRMED     = 'mfa.factor_confirmed';

    // A pending session's first factor completed its enrolment
    case BOOTSTRAP_ENROLLMENT_COMPLETED = 'mfa.bootstrap_enrollment_completed';
    case PASSKEY_ASSOCIATED             = 'mfa.passkey_associated';

    // A factor was disabled after too many failures
    case FACTOR_DISABLED = 'mfa.factor_disabled';

    // A factor disabled after too many failures was enabled again
    case FACTOR_ENABLED = 'mfa.factor_enabled';
    case FACTOR_REMOVED = 'mfa.factor_removed';
    case FACTOR_RENAMED = 'mfa.factor_renamed';
    case FACTORS_RESET  = 'mfa.factors_reset';

    // Verification was locked out after too many failures
    case LOCKED_OUT               = 'mfa.locked_out';
    case LOCKOUT_LIFTED           = 'mfa.lockout_lifted';
    case PREFERRED_FACTOR_CHANGED = 'mfa.preferred_factor_changed';
    case RECOVERY_CODE_USED       = 'mfa.recovery_code_used';
    case RECOVERY_CODES_LOW       = 'mfa.recovery_codes_low';
    case RECOVERY_CODES_GENERATED = 'mfa.recovery_codes_generated';
    case RECOVERY_CODES_REMOVED   = 'mfa.recovery_codes_removed';
    case VERIFICATION_FAILED      = 'mfa.verification_failed';
    case VERIFICATION_PASSED      = 'mfa.verification_passed';

    /** @var string The category every MFA code is stored under. */
    private const string CATEGORY = 'security';

    /** @var list<string> What an event about a factor keeps of it, beside the application. */
    private const array FACTOR = ['application', 'factor_id', 'factor_type'];

    /**
     * This case's definition, dropping every property it does not list.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        return EventDefinition::for($this)->category(self::CATEGORY)->retain(...$this->retained());
    }

    /**
     * Every property this case's code keeps.
     *
     * @return list<string>
     */
    #[\Override]
    public function properties(): array
    {
        return $this->retained();
    }

    /**
     * The properties this case's code keeps.
     *
     * @return list<string>
     */
    private function retained(): array
    {
        return match ($this) {
            self::CODE_SENT,
            self::FACTOR_DISABLED          => [...self::FACTOR, 'purpose'],
            self::FACTORS_RESET            => ['application', 'reenrollment_required', 'unreadable_factors'],
            self::LOCKED_OUT               => [...self::FACTOR, 'purpose', 'locked_until'],
            self::PREFERRED_FACTOR_CHANGED => [...self::FACTOR, 'previous_factor_id'],
            self::RECOVERY_CODE_USED,
            self::RECOVERY_CODES_LOW       => ['application', 'purpose', 'remaining'],
            self::RECOVERY_CODES_GENERATED => ['application', 'count', 'generation'],
            self::RECOVERY_CODES_REMOVED   => ['application'],
            self::VERIFICATION_FAILED,
            self::VERIFICATION_PASSED => [...self::FACTOR, 'type', 'purpose'],
            default                   => self::FACTOR,
        };
    }
}
