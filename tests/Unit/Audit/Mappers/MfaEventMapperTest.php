<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit\Mappers;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\Iam\Audit\Enums\MfaActivity;
use SineMacula\Laravel\Iam\Audit\Mappers\MfaEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\Snapshot;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\BootstrapEnrollmentCompleted;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned;
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
use Tests\Fixtures\Models\Person;

/**
 * Tests the mapper of MFA's events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaEventMapper::class)]
#[CoversClass(Snapshot::class)]
final class MfaEventMapperTest extends TestCase
{
    /** @var string The sign-in every event is about. */
    private const string SESSION = '01JB0000000000000000000000';

    /** @var string The challenge a code and its verification share. */
    private const string CHALLENGE = 'challenge-1';

    /** @var string The factor every event is about. */
    private const string FACTOR = '01JF0000000000000000000000';

    /**
     * Forget any morph map a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * Every one of MFA's events is provided for.
     *
     * @return void
     */
    public function testEveryEventIsProvidedFor(): void
    {
        $provided = array_map(static fn (array $row): string => $row[1]->value, iterator_to_array(self::provideEvents(), false));
        $codes    = array_map(static fn (MfaActivity $code): string => $code->value, MfaActivity::cases());

        self::assertEqualsCanonicalizing($codes, array_values(array_unique($provided)));
    }

    /**
     * Rows of `[event, code, properties]` for every one of MFA's events.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Contracts\MfaEvent, 1: \SineMacula\Laravel\Iam\Audit\Enums\MfaActivity, 2: array<string, mixed>}>
     */
    public static function provideEvents(): iterable
    {
        $context = self::context();
        $factor  = self::factor();
        $kept    = ['application' => 'api', 'factor_id' => self::FACTOR, 'factor_type' => 'totp'];
        $step    = ['application' => 'api', 'purpose' => 'step_up', 'factor_id' => self::FACTOR, 'factor_type' => 'totp'];
        $first   = ['application' => 'api', 'purpose' => 'sign_in', 'factor_id' => self::FACTOR, 'factor_type' => 'totp'];
        $actor   = new Actor(Person::class, '1');

        yield 'a code sent' => [new CodeSent($context, $factor, Purpose::STEP_UP, self::CHALLENGE), MfaActivity::CODE_SENT, $step];

        yield 'an enrolment started' => [new EnrollmentStarted($context, $factor), MfaActivity::ENROLLMENT_STARTED, $kept];

        yield 'an enrolment abandoned' => [new EnrollmentAbandoned($context, $factor), MfaActivity::ENROLLMENT_ABANDONED, $kept];

        yield 'an enrolment expired' => [new EnrollmentExpired($context, $factor), MfaActivity::ENROLLMENT_EXPIRED, $kept];

        yield 'a factor confirmed' => [new FactorConfirmed($context, $factor), MfaActivity::FACTOR_CONFIRMED, $kept];

        yield 'a bootstrap enrolment completed' => [new BootstrapEnrollmentCompleted($context, $factor), MfaActivity::BOOTSTRAP_ENROLLMENT_COMPLETED, $kept];

        yield 'a passkey associated' => [new PasskeyAssociated($context, $factor), MfaActivity::PASSKEY_ASSOCIATED, $kept];

        yield 'a factor disabled' => [new FactorDisabled($context, $factor, Purpose::SIGN_IN), MfaActivity::FACTOR_DISABLED, $first];

        yield 'a factor enabled' => [new FactorEnabled($context, $factor, $actor), MfaActivity::FACTOR_ENABLED, $kept];

        yield 'a factor removed' => [new FactorRemoved($context, $factor), MfaActivity::FACTOR_REMOVED, $kept];

        yield 'a factor renamed' => [new FactorRenamed($context, $factor, 'Old phone'), MfaActivity::FACTOR_RENAMED, $kept];

        yield 'factors reset' => [
            new FactorsReset($context, $actor, 'Lost their phone', false, 2),
            MfaActivity::FACTORS_RESET,
            ['application' => 'api', 'reenrollment_required' => false, 'unreadable_factors' => 2],
        ];

        yield 'a lockout applied' => [
            new LockoutApplied($context, $factor, CarbonImmutable::parse('2026-11-07 12:00:00'), Purpose::SIGN_IN),
            MfaActivity::LOCKED_OUT,
            [...$first, 'locked_until' => '2026-11-07T12:00:00.000000Z'],
        ];

        yield 'an identity\'s lockout applied' => [
            new LockoutApplied($context, null, CarbonImmutable::parse('2026-11-07 12:00:00'), Purpose::SIGN_IN),
            MfaActivity::LOCKED_OUT,
            ['application' => 'api', 'purpose' => 'sign_in', 'locked_until' => '2026-11-07T12:00:00.000000Z'],
        ];

        yield 'a lockout lifted' => [new LockoutLifted($context, $factor), MfaActivity::LOCKOUT_LIFTED, $kept];

        yield 'the preferred factor changed' => [
            new PreferredFactorChanged($context, $factor, self::factor('01JG0000000000000000000000')),
            MfaActivity::PREFERRED_FACTOR_CHANGED,
            [...$kept, 'previous_factor_id' => '01JG0000000000000000000000'],
        ];

        yield 'the first preferred factor' => [new PreferredFactorChanged($context, $factor), MfaActivity::PREFERRED_FACTOR_CHANGED, $kept];

        yield 'a recovery code used' => [
            new RecoveryCodeUsed($context, 4, Purpose::SIGN_IN),
            MfaActivity::RECOVERY_CODE_USED,
            ['application' => 'api', 'purpose' => 'sign_in', 'remaining' => 4],
        ];

        yield 'recovery codes low' => [
            new RecoveryCodesLow($context, 2, Purpose::SIGN_IN),
            MfaActivity::RECOVERY_CODES_LOW,
            ['application' => 'api', 'purpose' => 'sign_in', 'remaining' => 2],
        ];

        yield 'recovery codes generated' => [
            new RecoveryCodesGenerated($context, 10, 3),
            MfaActivity::RECOVERY_CODES_GENERATED,
            ['application' => 'api', 'count' => 10, 'generation' => 3],
        ];

        yield 'recovery codes removed' => [new RecoveryCodesRemoved($context), MfaActivity::RECOVERY_CODES_REMOVED, ['application' => 'api']];

        yield 'a verification failed' => [
            new VerificationFailed($context, $factor, 'totp', Purpose::STEP_UP, FailureReason::INVALID_CODE),
            MfaActivity::VERIFICATION_FAILED,
            [...$step, 'type' => 'totp'],
        ];

        yield 'a verification passed' => [new VerificationPassed($context, $factor, 'totp', Purpose::STEP_UP), MfaActivity::VERIFICATION_PASSED, [...$step, 'type' => 'totp']];
    }

    /**
     * Each event is recorded under its code, keeping what its code keeps.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @param  \SineMacula\Laravel\Iam\Audit\Enums\MfaActivity  $code
     * @param  array<string, mixed>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEachEventIsRecordedUnderItsCode(MfaEvent $event, MfaActivity $code, array $properties): void
    {
        $snapshot = self::snapshotOf($event);

        self::assertSame($code->value, $snapshot->code?->value);
        self::assertSame($properties, $snapshot->properties ?? []);
    }

    /**
     * An event that is not one of MFA's is skipped.
     *
     * @return void
     */
    public function testAnotherEventIsSkipped(): void
    {
        $other = new class implements MfaEvent {
            /**
             * No context.
             *
             * @return array<string, int|string|null>
             */
            #[\Override]
            public function context(): array
            {
                return [];
            }

            /**
             * No purpose.
             *
             * @return ?\SineMacula\Laravel\Mfa\Enums\Purpose
             */
            #[\Override]
            public function purpose(): ?Purpose
            {
                return null;
            }
        };

        self::assertNull((new MfaEventMapper)->map($other, new PendingRecord));
        self::assertNull((new MfaEventMapper)->map(new \stdClass, new PendingRecord));
    }

    /**
     * A failed verification carries its reason and a lockout is denied.
     *
     * @return void
     */
    public function testTheOutcomeIsTheEvents(): void
    {
        $failed = self::snapshotOf(new VerificationFailed(self::context(), null, null, Purpose::SIGN_IN, FailureReason::REPLAYED));
        $locked = self::snapshotOf(new LockoutApplied(self::context(), null, CarbonImmutable::now(), Purpose::SIGN_IN));
        $passed = self::snapshotOf(new VerificationPassed(self::context(), null, 'recovery_code', Purpose::SIGN_IN));

        self::assertSame([Outcome::FAILURE, 'replayed'], [$failed->outcome, $failed->reason]);
        self::assertSame([Outcome::DENIED, null], [$locked->outcome, $locked->reason]);
        self::assertSame([Outcome::SUCCESS, null], [$passed->outcome, $passed->reason]);
    }

    /**
     * The identity's own action is the identity's, from MFA's context.
     *
     * @return void
     */
    public function testTheIdentitysOwnActionIsAttributedFromTheContext(): void
    {
        $record   = new PendingRecord;
        $snapshot = (new MfaEventMapper)->map(new FactorConfirmed(self::context(), self::factor()), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->actor?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->principal?->toArray());
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => 'tenant-9'], $snapshot->tenant?->toArray());
        self::assertSame('api', $snapshot->guard);
        self::assertSame(self::SESSION, $snapshot->sessionId);
        self::assertSame(['192.0.2.10', 'iam-tests'], [$snapshot->ip, $snapshot->userAgent]);
        self::assertSame('session:' . self::SESSION, $snapshot->correlationId);
    }

    /**
     * Integer ids and the morph map are read as every member's are.
     *
     * @return void
     */
    public function testIntegerIdsAndTheMorphMapAreRead(): void
    {
        Relation::morphMap(['person' => Person::class]);

        $snapshot = self::snapshotOf(new FactorRenamed([...self::context(), 'identity_id' => 7, 'tenant_id' => 9, 'session_id' => 42], self::factor()));

        self::assertSame(['type' => 'person', 'id' => '7'], $snapshot->actor?->toArray());
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => '9'], $snapshot->tenant?->toArray());
        self::assertSame('42', $snapshot->sessionId);
    }

    /**
     * A context naming nothing gives explicitly no one and none of the rest.
     *
     * @return void
     */
    public function testAnEmptyContextGivesNothing(): void
    {
        $record   = new PendingRecord;
        $snapshot = (new MfaEventMapper)->map(new RecoveryCodesRemoved(['identity_type' => '', 'session_id' => '']), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertNull($snapshot->actor);
        self::assertNull($snapshot->subject);
        self::assertNull($snapshot->guard);
        self::assertNull($snapshot->sessionId);
        self::assertNull($snapshot->correlationId);
        self::assertSame([], $snapshot->properties ?? []);
    }

    /**
     * Rows of `[event]` naming an operator who acted on someone else's factors.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Contracts\MfaEvent}>
     */
    public static function provideOperatorsActions(): iterable
    {
        $actor = new Actor(Person::class, '1');

        yield 'a reset' => [new FactorsReset(self::context(), $actor, 'Lost their phone')];

        yield 'a removal' => [new FactorRemoved(self::context(), self::factor(), $actor)];

        yield 'a factor enabled' => [new FactorEnabled(self::context(), self::factor(), $actor)];

        yield 'a lockout lifted' => [new LockoutLifted(self::context(), null, $actor)];

        yield 'recovery codes generated' => [new RecoveryCodesGenerated(self::context(), 10, 1, $actor)];

        yield 'recovery codes removed' => [new RecoveryCodesRemoved(self::context(), $actor)];
    }

    /**
     * An operator's action is the operator's, on the identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @return void
     */
    #[DataProvider('provideOperatorsActions')]
    public function testAnOperatorsActionIsTheOperators(MfaEvent $event): void
    {
        $record   = new PendingRecord;
        $snapshot = (new MfaEventMapper)->map($event, $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertSame(['type' => Person::class, 'id' => '1'], $snapshot->actor?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
        self::assertNull($snapshot->principal);
        self::assertSame('tenant-9', $snapshot->tenant?->id);
    }

    /**
     * Rows of `[event]` MFA made by itself, explicitly by no one.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Contracts\MfaEvent}>
     */
    public static function provideActionsOfNoOne(): iterable
    {
        yield 'an enrolment expired' => [new EnrollmentExpired(self::context(), self::factor())];

        yield 'a factor disabled' => [new FactorDisabled(self::context(), self::factor(), Purpose::SIGN_IN)];

        yield 'a lockout applied' => [new LockoutApplied(self::context(), null, CarbonImmutable::now(), Purpose::SIGN_IN)];
    }

    /**
     * What MFA did by itself is explicitly by no one.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @return void
     */
    #[DataProvider('provideActionsOfNoOne')]
    public function testWhatMfaDidByItselfIsByNoOne(MfaEvent $event): void
    {
        $record = new PendingRecord;

        (new MfaEventMapper)->map($event, $record);

        self::assertTrue($record->isActorSettled());
        self::assertNull($record->snapshot()->actor);
    }

    /**
     * A failed verification is by no one.
     *
     * @return void
     */
    public function testAFailedVerificationIsByNoOne(): void
    {
        $record   = new PendingRecord;
        $snapshot = (new MfaEventMapper)->map(new VerificationFailed(self::context(), self::factor(), 'totp', Purpose::STEP_UP, FailureReason::INVALID_CODE), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertNull($snapshot->actor);
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->principal?->toArray());
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => 'tenant-9'], $snapshot->tenant?->toArray());
    }

    /**
     * Rows of `[event]` naming no operator.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Contracts\MfaEvent}>
     */
    public static function provideOwnActionsNamingNoOperator(): iterable
    {
        yield 'the identity\'s lockout lifted' => [new LockoutLifted(self::context())];

        yield 'a factor\'s lockout lifted' => [new LockoutLifted(self::context(), self::factor())];

        yield 'a removal' => [new FactorRemoved(self::context(), self::factor())];

        yield 'recovery codes generated' => [new RecoveryCodesGenerated(self::context(), 10, 1)];

        yield 'recovery codes removed' => [new RecoveryCodesRemoved(self::context())];
    }

    /**
     * An action naming no operator is the identity's own.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MfaEvent  $event
     * @return void
     */
    #[DataProvider('provideOwnActionsNamingNoOperator')]
    public function testAnActionNamingNoOperatorIsTheIdentitys(MfaEvent $event): void
    {
        $record   = new PendingRecord;
        $snapshot = (new MfaEventMapper)->map($event, $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->actor?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->principal?->toArray());
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => 'tenant-9'], $snapshot->tenant?->toArray());
    }

    /**
     * Rows of `[event]` of an enrolment abandoned, one per cause.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned}>
     */
    public static function provideAbandonments(): iterable
    {
        $reset = [...self::context(), 'application' => null, 'session_id' => null];

        yield 'by an operator\'s reset' => [new EnrollmentAbandoned($reset, self::factor())];

        yield 'once its confirmation attempts run out' => [new EnrollmentAbandoned(self::context(), self::factor())];

        yield 'by its replacement' => [new EnrollmentAbandoned(self::context(), self::factor())];

        yield 'by its cancellation' => [new EnrollmentAbandoned(self::context(), self::factor())];
    }

    /**
     * An enrolment abandoned is the caller's, on the identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned  $event
     * @return void
     */
    #[DataProvider('provideAbandonments')]
    public function testAnEnrolmentAbandonedIsTheCallers(EnrollmentAbandoned $event): void
    {
        $record   = new PendingRecord;
        $snapshot = (new MfaEventMapper)->map($event, $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertFalse($record->isActorSettled());
        self::assertNull($snapshot->actor);
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
        self::assertNull($snapshot->principal);
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => 'tenant-9'], $snapshot->tenant?->toArray());
    }

    /**
     * A challenge's events are correlated by it, ahead of the session.
     *
     * @return void
     */
    public function testAChallengesEventsAreCorrelatedByIt(): void
    {
        $sent   = self::snapshotOf(new CodeSent(self::context(), self::factor(), Purpose::SIGN_IN, self::CHALLENGE));
        $failed = self::snapshotOf(new VerificationFailed(self::context(), self::factor(), 'email', Purpose::SIGN_IN, FailureReason::INVALID_CODE, self::CHALLENGE));
        $passed = self::snapshotOf(new VerificationPassed(self::context(), self::factor(), 'email', Purpose::SIGN_IN, self::CHALLENGE));

        self::assertSame(['mfa:' . self::CHALLENGE], array_values(array_unique([$sent->correlationId, $failed->correlationId, $passed->correlationId])));
    }

    /**
     * The snapshot of the record the mapper describes the event on.
     *
     * @param  object  $event
     * @return \SineMacula\Laravel\AuditLog\Records\PendingSnapshot
     */
    private static function snapshotOf(object $event): PendingSnapshot
    {
        $record = (new MfaEventMapper)->map($event, new PendingRecord);

        self::assertInstanceOf(PendingRecord::class, $record);

        return $record->snapshot();
    }

    /**
     * MFA's context for the person in the tenant, on the sign-in.
     *
     * @return array<string, int|string|null>
     */
    private static function context(): array
    {
        return [
            'identity_type'  => Person::class,
            'identity_id'    => '7',
            'principal_type' => Person::class,
            'principal_id'   => '7',
            'tenant_id'      => 'tenant-9',
            'application'    => 'api',
            'session_id'     => self::SESSION,
            'ip'             => '192.0.2.10',
            'user_agent'     => 'iam-tests',
        ];
    }

    /**
     * A summary of a confirmed TOTP factor.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Mfa\Factors\FactorSummary
     */
    private static function factor(string $id = self::FACTOR): FactorSummary
    {
        return new FactorSummary($id, 'totp', 'My phone', null, FactorStatus::CONFIRMED, true, null);
    }
}
