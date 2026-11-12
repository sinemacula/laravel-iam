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
 * Records MFA's events under their `MfaActivity` codes, from each event alone.
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
     * The code the event is recorded under; `null` for any other event.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @return ?\SineMacula\Laravel\Iam\Audit\Enums\MfaActivity
     */
    private static function code(MfaEvent $event): ?MfaActivity
    {
        return self::CODES[$event::class] ?? null;
    }

    /**
     * Who the record says acted when the event names no operator; MFA's
     * `EnrollmentAbandoned` names no cause or operator, so it is the caller's.
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
     * The operator the event names as acting on someone else's factors.
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
     * The application, purpose, factor and event details, less any null.
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
