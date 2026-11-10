<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Enums;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\Iam\Audit\Contracts\ListsProperties;

/**
 * The `mfa.*` codes MFA's events are recorded under (IAM-9.2), one for each of
 * MFA's events: codes sent, enrolments, factor changes, resets, lockouts,
 * recovery codes and verifications.
 *
 * Every definition is version 1, in the `security` category, and drops every
 * property it does not list. Each keeps the MFA application the event ran
 * through; one about a factor keeps the factor's id and type, never its label
 * or its masked destination; and a reset never keeps the reason an operator
 * gave in words, which is free text, not a reason code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
enum MfaActivity: string implements ListsProperties
{
    // A factor's code was sent
    case CODE_SENT = 'mfa.code_sent';

    // A factor's enrolment was started
    case ENROLLMENT_STARTED = 'mfa.enrollment_started';

    // A factor's enrolment was abandoned for another
    case ENROLLMENT_ABANDONED = 'mfa.enrollment_abandoned';

    // A factor's enrolment expired unconfirmed
    case ENROLLMENT_EXPIRED = 'mfa.enrollment_expired';

    // A factor was confirmed
    case FACTOR_CONFIRMED = 'mfa.factor_confirmed';

    // A pending session's first factor completed its enrolment
    case BOOTSTRAP_ENROLLMENT_COMPLETED = 'mfa.bootstrap_enrollment_completed';

    // A passkey was associated as a factor
    case PASSKEY_ASSOCIATED = 'mfa.passkey_associated';

    // A factor was disabled after too many failures
    case FACTOR_DISABLED = 'mfa.factor_disabled';

    // A factor disabled after too many failures was enabled again
    case FACTOR_ENABLED = 'mfa.factor_enabled';

    // A factor was removed
    case FACTOR_REMOVED = 'mfa.factor_removed';

    // A factor was renamed
    case FACTOR_RENAMED = 'mfa.factor_renamed';

    // An identity's factors were reset
    case FACTORS_RESET = 'mfa.factors_reset';

    // Verification was locked out after too many failures
    case LOCKED_OUT = 'mfa.locked_out';

    // A lockout was lifted
    case LOCKOUT_LIFTED = 'mfa.lockout_lifted';

    // The preferred factor changed
    case PREFERRED_FACTOR_CHANGED = 'mfa.preferred_factor_changed';

    // A recovery code was used
    case RECOVERY_CODE_USED = 'mfa.recovery_code_used';

    // The recovery codes left fell low
    case RECOVERY_CODES_LOW = 'mfa.recovery_codes_low';

    // A set of recovery codes was generated
    case RECOVERY_CODES_GENERATED = 'mfa.recovery_codes_generated';

    // The recovery codes were removed
    case RECOVERY_CODES_REMOVED = 'mfa.recovery_codes_removed';

    // A verification failed
    case VERIFICATION_FAILED = 'mfa.verification_failed';

    // A verification passed
    case VERIFICATION_PASSED = 'mfa.verification_passed';

    /** @var string The category every MFA code is stored under. */
    private const string CATEGORY = 'security';

    /** @var list<string> What an event about a factor keeps of it, beside the application. */
    private const array FACTOR = ['application', 'factor_id', 'factor_type'];

    /**
     * The definition of this case's code: version 1, the `security` category,
     * the properties it lists kept and every other one dropped.
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
