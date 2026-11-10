<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Mappers;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\Iam\Audit\Correlation;
use SineMacula\Laravel\Iam\Audit\Enums\MfaActivity;
use SineMacula\Laravel\Iam\Audit\Mappers\Enums\Attribution;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\BootstrapEnrollmentCompleted;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned;
use SineMacula\Laravel\Mfa\Events\EnrollmentEvent;
use SineMacula\Laravel\Mfa\Events\EnrollmentExpired;
use SineMacula\Laravel\Mfa\Events\EnrollmentStarted;
use SineMacula\Laravel\Mfa\Events\FactorConfirmed;
use SineMacula\Laravel\Mfa\Events\FactorDisabled;
use SineMacula\Laravel\Mfa\Events\FactorEnabled;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Events\FactorRenamed;
use SineMacula\Laravel\Mfa\Events\FactorsReset;
use SineMacula\Laravel\Mfa\Events\LockoutApplied;
use SineMacula\Laravel\Mfa\Events\LockoutLifted;
use SineMacula\Laravel\Mfa\Events\PasskeyAssociated;
use SineMacula\Laravel\Mfa\Events\PreferredFactorChanged;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesGenerated;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesLow;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesRemoved;
use SineMacula\Laravel\Mfa\Events\RecoveryCodeUsed;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Records MFA's events (`MfaEvent`) in audit-log, from each event alone
 * (IAM-9.1, IAM-9.4), each under its own `MfaActivity` code.
 *
 * A failed verification's reason is the record's (MFA conceals none from the
 * client), and a lockout is recorded as denied. The record's actor is the
 * operator the event names (a reset, a lifted lockout, a factor its failures
 * disabled enabled again, a removal, recovery codes made or removed for someone
 * else), else the identity for its own action, explicitly no one for a failed
 * verification, whose author was never proven, and for what MFA did by itself
 * (an enrolment expired, a factor disabled or a lockout applied after too many
 * failures), and the caller for an enrolment abandoned. A lockout lifted,
 * factor removed or recovery codes made or removed with no operator named is
 * the identity's own, as MFA documents a lift with no actor as the identity's.
 * MFA abandons an enrolment for the identity replacing or cancelling it, for an
 * operator resetting its factors and by itself once its confirmation attempts
 * run out, and names neither cause nor operator, so the record leaves its actor
 * to the contributors (the person or the operator serving the call) rather than
 * name the identity as having acted. Its subject is the identity, and its
 * principal, tenant, session and client MFA's context's; the MFA application
 * stands for the guard, which is the same name in this package. A code sent and
 * a verification are correlated by their challenge (`mfa:{challenge}`), which
 * `laravel-authentication`'s refusal of a factor's code names too, and every
 * other event by its session.
 *
 * Both events of one confirmation (`VerificationPassed`, `FactorConfirmed`) and
 * of one recovery code's use (`RecoveryCodeUsed`, `RecoveryCodesLow`) are two
 * facts and are recorded once each. A reset's reason, which an operator gives
 * in words, is never recorded: reasons are codes.
 *
 * It reads nothing but the event and the morph map, and keeps nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MfaEventMapper implements EventMapper
{
    /** @var array<class-string<\SineMacula\Laravel\Mfa\Contracts\MfaEvent>, \SineMacula\Laravel\Iam\Audit\Enums\MfaActivity> The code of each of MFA's events. */
    private const array CODES = [
        CodeSent::class                     => MfaActivity::CODE_SENT,
        EnrollmentStarted::class            => MfaActivity::ENROLLMENT_STARTED,
        EnrollmentAbandoned::class          => MfaActivity::ENROLLMENT_ABANDONED,
        EnrollmentExpired::class            => MfaActivity::ENROLLMENT_EXPIRED,
        FactorConfirmed::class              => MfaActivity::FACTOR_CONFIRMED,
        BootstrapEnrollmentCompleted::class => MfaActivity::BOOTSTRAP_ENROLLMENT_COMPLETED,
        PasskeyAssociated::class            => MfaActivity::PASSKEY_ASSOCIATED,
        FactorDisabled::class               => MfaActivity::FACTOR_DISABLED,
        FactorEnabled::class                => MfaActivity::FACTOR_ENABLED,
        FactorRemoved::class                => MfaActivity::FACTOR_REMOVED,
        FactorRenamed::class                => MfaActivity::FACTOR_RENAMED,
        FactorsReset::class                 => MfaActivity::FACTORS_RESET,
        LockoutApplied::class               => MfaActivity::LOCKED_OUT,
        LockoutLifted::class                => MfaActivity::LOCKOUT_LIFTED,
        PreferredFactorChanged::class       => MfaActivity::PREFERRED_FACTOR_CHANGED,
        RecoveryCodeUsed::class             => MfaActivity::RECOVERY_CODE_USED,
        RecoveryCodesLow::class             => MfaActivity::RECOVERY_CODES_LOW,
        RecoveryCodesGenerated::class       => MfaActivity::RECOVERY_CODES_GENERATED,
        RecoveryCodesRemoved::class         => MfaActivity::RECOVERY_CODES_REMOVED,
        VerificationFailed::class           => MfaActivity::VERIFICATION_FAILED,
        VerificationPassed::class           => MfaActivity::VERIFICATION_PASSED,
    ];

    /**
     * Describe the event on the record, or skip it.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord
    {
        $code = $event instanceof MfaEvent ? self::code($event) : null;

        if ($code === null) {
            return null;
        }

        $snapshot = Snapshot::ofMfa($event->context());

        Snapshot::describe($record, $code, self::properties($event));

        $correlation = Correlation::first(Correlation::mfaChallenge(self::challenge($event)), Correlation::session($snapshot->sessionId));

        if ($correlation !== null) {
            $record->correlatedWith($correlation);
        }

        if ($event instanceof VerificationFailed) {
            $record->failed($event->reason);
        }

        if ($event instanceof LockoutApplied) {
            $record->denied();
        }

        return $snapshot->attribute($record, self::attribution($event), $snapshot->identity, self::operator($event));
    }

    /**
     * The code the event is recorded under, or `null` for an event that is not
     * one of MFA's own.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @return ?\SineMacula\Laravel\Iam\Audit\Enums\MfaActivity
     */
    private static function code(MfaEvent $event): ?MfaActivity
    {
        return self::CODES[$event::class] ?? null;
    }

    /**
     * Who the record says acted when the event names no operator.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @return \SineMacula\Laravel\Iam\Audit\Mappers\Enums\Attribution
     */
    private static function attribution(MfaEvent $event): Attribution
    {
        return match (true) {
            $event instanceof EnrollmentExpired,
            $event instanceof FactorDisabled,
            $event instanceof LockoutApplied,
            $event instanceof VerificationFailed  => Attribution::NOBODY,
            $event instanceof EnrollmentAbandoned => Attribution::CALLER,
            default                               => Attribution::SUBJECT,
        };
    }

    /**
     * The operator the event names as having acted on someone else's factors,
     * if any.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function operator(MfaEvent $event): ?Reference
    {
        $actor = match (true) {
            $event instanceof FactorsReset,
            $event instanceof FactorEnabled,
            $event instanceof FactorRemoved,
            $event instanceof LockoutLifted,
            $event instanceof RecoveryCodesGenerated,
            $event instanceof RecoveryCodesRemoved => $event->actor,
            default                                => null,
        };

        return $actor instanceof Actor ? References::of($actor->type, $actor->id) : null;
    }

    /**
     * The factor the event is about, if any.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @return ?\SineMacula\Laravel\Mfa\Factors\FactorSummary
     */
    private static function factor(MfaEvent $event): ?FactorSummary
    {
        return match (true) {
            $event instanceof CodeSent,
            $event instanceof EnrollmentEvent,
            $event instanceof FactorDisabled,
            $event instanceof FactorEnabled,
            $event instanceof FactorRemoved,
            $event instanceof FactorRenamed,
            $event instanceof LockoutApplied,
            $event instanceof LockoutLifted,
            $event instanceof PreferredFactorChanged,
            $event instanceof VerificationFailed,
            $event instanceof VerificationPassed => $event->factor,
            default                              => null,
        };
    }

    /**
     * The challenge the event names, if any.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @return ?string
     */
    private static function challenge(MfaEvent $event): ?string
    {
        return match (true) {
            $event instanceof CodeSent,
            $event instanceof VerificationFailed,
            $event instanceof VerificationPassed => $event->challengeId,
            default                              => null,
        };
    }

    /**
     * The properties the event describes itself with: the application, the
     * purpose, the factor and what the event adds; a value the event does not
     * have is left out. The code's definition decides which are kept.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @return array<string, mixed>
     */
    private static function properties(MfaEvent $event): array
    {
        $factor = self::factor($event);

        return array_filter([
            'application' => $event->context()['application'] ?? null,
            'purpose'     => $event->purpose(),
            'factor_id'   => $factor?->id,
            'factor_type' => $factor?->type,
            ...self::details($event),
        ], static fn (mixed $value): bool => $value !== null);
    }

    /**
     * What the event adds to its context, its purpose and its factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @return array<string, mixed>
     */
    private static function details(MfaEvent $event): array
    {
        return match (true) {
            $event instanceof FactorsReset           => ['reenrollment_required' => $event->reenrollmentRequired, 'unreadable_factors' => $event->unreadableFactors],
            $event instanceof LockoutApplied         => ['locked_until' => $event->lockedUntil],
            $event instanceof PreferredFactorChanged => ['previous_factor_id' => $event->previous?->id],
            $event instanceof RecoveryCodeUsed,
            $event instanceof RecoveryCodesLow       => ['remaining' => $event->remaining],
            $event instanceof RecoveryCodesGenerated => ['count' => $event->count, 'generation' => $event->generation],
            $event instanceof VerificationFailed,
            $event instanceof VerificationPassed => ['type' => $event->type],
            default                              => [],
        };
    }
}
