<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit\Mappers;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\ApiKeyIssued;
use SineMacula\Laravel\Authentication\Events\ApiKeyRevoked;
use SineMacula\Laravel\Authentication\Events\ApiKeyRotated;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\ClientCredentialsGranted;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\ExternalResultRedeemed;
use SineMacula\Laravel\Authentication\Events\ExternalResultUnlinked;
use SineMacula\Laravel\Authentication\Events\IdentifierChanged;
use SineMacula\Laravel\Authentication\Events\IdentifierChangeRequested;
use SineMacula\Laravel\Authentication\Events\IdentifierVerified;
use SineMacula\Laravel\Authentication\Events\PasskeyAdded;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Events\PasskeyUsed;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionActivated;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionPending;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Events\SteppedUp;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Iam\Audit\Correlation;
use SineMacula\Laravel\Iam\Audit\Enums\AuthenticationActivity;
use SineMacula\Laravel\Iam\Audit\Enums\SessionActivity;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthenticationEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\Snapshot;
use SineMacula\Laravel\Iam\Audit\References;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;

/**
 * Tests the mapper of `laravel-authentication`'s events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationEventMapper::class)]
#[CoversClass(Snapshot::class)]
final class AuthenticationEventMapperTest extends TestCase
{
    /** @var string The session every event is about. */
    private const string SESSION = '01JB0000000000000000000000';

    /** @var string The tenant every event acts in. */
    private const string TENANT = 'tenant-9';

    /** @var string The connection an external result came through. */
    private const string CONNECTION = '01JC0000000000000000000000';

    /** @var string The request an external result answered. */
    private const string REFERENCE = 'reference-1';

    /** @var string The challenge a refusal answered. */
    private const string CHALLENGE = 'challenge-1';

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
     * Rows of `[event, code]` for every event recorded under its own code.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent, 1: \BackedEnum}>
     */
    public static function provideEvents(): iterable
    {
        $context = self::context();
        $later   = CarbonImmutable::parse('2026-11-07 12:00:00');

        yield 'a sign-in' => [new SignedIn($context, false), CapturedActivity::SIGNED_IN];

        yield 'a session created' => [new SessionCreated($context), SessionActivity::CREATED];

        yield 'a pending session' => [new SessionPending($context, ['additional_factor'], $later), SessionActivity::PENDING];

        yield 'a session activated' => [new SessionActivated($context), SessionActivity::ACTIVATED];

        yield 'a return to pending' => [new SessionReturnedToPending($context, ['additional_factor'], $later, AuthenticationFlow::SWITCH), SessionActivity::RETURNED_TO_PENDING];

        yield 'a sign-out' => [new SessionRevoked($context, RevocationReason::SIGNED_OUT), CapturedActivity::SIGNED_OUT];

        yield 'a revocation' => [new SessionRevoked($context, RevocationReason::REVOKED), SessionActivity::REVOKED];

        yield 'a sign-out everywhere' => [new SignedOutEverywhere($context, RevocationReason::SIGNED_OUT_EVERYWHERE, 3, $later), SessionActivity::SIGNED_OUT_EVERYWHERE];

        yield 'a refresh' => [new Refreshed($context), SessionActivity::REFRESHED];

        yield 'a switch' => [new PrincipalSwitched($context, Person::class, '6', 'tenant-8', true, true), SessionActivity::SWITCHED];

        yield 'a step-up' => [new SteppedUp($context, ProofKind::ADDITIONAL_FACTOR), SessionActivity::STEPPED_UP];

        yield 'a reauthentication' => [new Reauthenticated($context), SessionActivity::REAUTHENTICATED];

        yield 'an external result redeemed' => [new ExternalResultRedeemed($context, AuthenticationFlow::SIGN_IN), AuthenticationActivity::EXTERNAL_RESULT_REDEEMED];

        yield 'an external result unlinked' => [new ExternalResultUnlinked($context, 'https://idp.example.test'), AuthenticationActivity::EXTERNAL_RESULT_UNLINKED];

        yield 'an identifier change requested' => [
            new IdentifierChangeRequested($context, 'email', 'new@example.test', $later),
            AuthenticationActivity::IDENTIFIER_CHANGE_REQUESTED,
        ];

        yield 'an identifier changed' => [new IdentifierChanged($context, 'email', 'old@example.test', 'new@example.test', $later), AuthenticationActivity::IDENTIFIER_CHANGED];

        yield 'an email address verified' => [new IdentifierVerified($context, 'email'), CapturedActivity::EMAIL_VERIFIED];

        yield 'a phone number verified' => [new IdentifierVerified($context, 'phone'), AuthenticationActivity::IDENTIFIER_VERIFIED];

        yield 'a password set at registration' => [new PasswordSet($context, PasswordFlow::REGISTRATION), AuthenticationActivity::PASSWORD_SET];

        yield 'a password changed' => [new PasswordSet($context, PasswordFlow::CHANGE), AuthenticationActivity::PASSWORD_CHANGED];

        yield 'a password reset' => [new PasswordSet($context, PasswordFlow::RESET), CapturedActivity::PASSWORD_RESET];

        yield 'a password established' => [new PasswordSet($context, PasswordFlow::ESTABLISHMENT), AuthenticationActivity::PASSWORD_ESTABLISHED];

        yield 'a passkey added' => [new PasskeyAdded($context), AuthenticationActivity::PASSKEY_ADDED];

        yield 'a passkey removed' => [new PasskeyRemoved($context), AuthenticationActivity::PASSKEY_REMOVED];

        yield 'a passkey used' => [new PasskeyUsed($context), AuthenticationActivity::PASSKEY_USED];

        yield 'an API key issued' => [new ApiKeyIssued($context), AuthenticationActivity::API_KEY_ISSUED];

        yield 'an API key revoked' => [new ApiKeyRevoked($context), AuthenticationActivity::API_KEY_REVOKED];

        yield 'an API key rotated' => [new ApiKeyRotated($context, 'key-0'), AuthenticationActivity::API_KEY_ROTATED];

        yield 'client credentials granted' => [new ClientCredentialsGranted($context), AuthenticationActivity::CLIENT_CREDENTIALS_GRANTED];
    }

    /**
     * Each event is recorded under its code, as a success.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @param  \BackedEnum  $code
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEachEventIsRecordedUnderItsCode(AuthenticationEvent $event, \BackedEnum $code): void
    {
        $snapshot = self::snapshotOf($event);

        self::assertSame($code->value, $snapshot->code?->value);
        self::assertSame(Outcome::SUCCESS, $snapshot->outcome);
        self::assertNull($snapshot->reason);
    }

    /**
     * Rows of `[event]` that are skipped.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent}>
     */
    public static function provideSkippedEvents(): iterable
    {
        yield 'a principal assigned' => [new PrincipalAssigned(self::context())];

        yield 'a session authenticated' => [new SessionAuthenticated(self::context())];

        yield 'a refresh\'s sign-in' => [new SignedIn(self::context(), true)];
    }

    /**
     * Noise is skipped.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return void
     */
    #[DataProvider('provideSkippedEvents')]
    public function testNoiseIsSkipped(AuthenticationEvent $event): void
    {
        self::assertNull((new AuthenticationEventMapper)->map($event, new PendingRecord));
    }

    /**
     * An event that is not one of `laravel-authentication`'s is skipped.
     *
     * @return void
     */
    public function testAnotherEventIsSkipped(): void
    {
        self::assertNull((new AuthenticationEventMapper)->map(new \stdClass, new PendingRecord));
    }

    /**
     * Every flow is provided for.
     *
     * @return void
     */
    public function testEveryFlowIsProvidedFor(): void
    {
        $flows = array_map(static fn (array $row): AuthenticationFlow => $row[0], iterator_to_array(self::provideFlows(), false));

        self::assertSame(AuthenticationFlow::cases(), $flows);
    }

    /**
     * Rows of `[flow, code]` for every flow a refusal is recorded by.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow, 1: \BackedEnum}>
     */
    public static function provideFlows(): iterable
    {
        yield 'sign_in' => [AuthenticationFlow::SIGN_IN, CapturedActivity::SIGN_IN_FAILED];

        yield 'bearer' => [AuthenticationFlow::BEARER, AuthenticationActivity::REQUEST_REJECTED];

        yield 'refresh' => [AuthenticationFlow::REFRESH, SessionActivity::REFRESH_FAILED];

        yield 'switch' => [AuthenticationFlow::SWITCH, SessionActivity::SWITCH_FAILED];

        yield 'sign_out' => [AuthenticationFlow::SIGN_OUT, SessionActivity::SIGN_OUT_FAILED];

        yield 'code_request' => [AuthenticationFlow::CODE_REQUEST, AuthenticationActivity::CODE_REQUEST_FAILED];

        yield 'identifier_verification' => [AuthenticationFlow::IDENTIFIER_VERIFICATION, AuthenticationActivity::IDENTIFIER_VERIFICATION_FAILED];

        yield 'api_key' => [AuthenticationFlow::API_KEY, AuthenticationActivity::API_KEY_REJECTED];

        yield 'client_credentials' => [AuthenticationFlow::CLIENT_CREDENTIALS, AuthenticationActivity::CLIENT_CREDENTIALS_FAILED];

        yield 'password_reset' => [AuthenticationFlow::PASSWORD_RESET, AuthenticationActivity::PASSWORD_RESET_FAILED];

        yield 'identifier_change' => [AuthenticationFlow::IDENTIFIER_CHANGE, AuthenticationActivity::IDENTIFIER_CHANGE_FAILED];

        yield 'step_up' => [AuthenticationFlow::STEP_UP, SessionActivity::STEP_UP_FAILED];

        yield 'reauthentication' => [AuthenticationFlow::REAUTHENTICATION, SessionActivity::REAUTHENTICATION_FAILED];

        yield 'factor_code' => [AuthenticationFlow::FACTOR_CODE, AuthenticationActivity::FACTOR_CODE_FAILED];

        yield 'password_change' => [AuthenticationFlow::PASSWORD_CHANGE, AuthenticationActivity::PASSWORD_CHANGE_FAILED];

        yield 'factor_change' => [AuthenticationFlow::FACTOR_CHANGE, SessionActivity::FACTOR_RECHECK_FAILED];
    }

    /**
     * A refusal is recorded by its flow, failed and by no one.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  \BackedEnum  $code
     * @return void
     */
    #[DataProvider('provideFlows')]
    public function testARefusalIsRecordedByItsFlow(AuthenticationFlow $flow, \BackedEnum $code): void
    {
        $record   = new PendingRecord;
        $event    = new AuthenticationFailed(self::context(), $flow, FailureReason::INVALID_CREDENTIALS, 'ada@example.test', 30);
        $snapshot = (new AuthenticationEventMapper)->map($event, $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertSame($code->value, $snapshot->code?->value);
        self::assertSame(Outcome::FAILURE, $snapshot->outcome);
        self::assertSame('invalid_credentials', $snapshot->reason);
        self::assertTrue($record->isActorSettled());
        self::assertNull($snapshot->actor);
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
        self::assertSame('ada@example.test', $snapshot->identifier);
        self::assertSame('session:' . self::SESSION, $snapshot->correlationId);
        self::assertArrayNotHasKey('identifier', $snapshot->properties ?? []);
        self::assertArrayNotHasKey('concealed', $snapshot->properties ?? []);
    }

    /**
     * Only a refusal waits for its transaction to end.
     *
     * @return void
     */
    public function testOnlyARefusalWaitsForItsTransactionToEnd(): void
    {
        $refusal = new AuthenticationFailed(self::context(), AuthenticationFlow::SIGN_IN, FailureReason::INVALID_CREDENTIALS);

        self::assertSame(Timing::AFTER_TRANSACTION, self::snapshotOf($refusal)->timing);
        self::assertNull(self::snapshotOf(new SessionCreated(self::context()))->timing);
    }

    /**
     * A sign-in refusal keeps no property; any other keeps its method and wait.
     *
     * @return void
     */
    public function testOnlyTheOwnCodesOfRefusalsKeepProperties(): void
    {
        $signIn = self::snapshotOf(new AuthenticationFailed(self::context(), AuthenticationFlow::SIGN_IN, FailureReason::INVALID_CREDENTIALS, null, 30));
        $bearer = self::snapshotOf(new AuthenticationFailed(self::context(), AuthenticationFlow::BEARER, FailureReason::RATE_LIMITED, null, 30));

        self::assertSame([], $signIn->properties ?? []);
        self::assertSame(['method' => 'password', 'retry_after' => 30], $bearer->properties);
        self::assertNull($signIn->identifier);
    }

    /**
     * A sign-in out of attempts is audit-log's lockout, about no one.
     *
     * @return void
     */
    public function testASignInOutOfAttemptsIsALockout(): void
    {
        $record   = new PendingRecord;
        $event    = new AuthenticationFailed(self::context(), AuthenticationFlow::SIGN_IN, FailureReason::RATE_LIMITED, 'ada@example.test', 30);
        $snapshot = (new AuthenticationEventMapper)->map($event, $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertSame(CapturedActivity::LOCKED_OUT->value, $snapshot->code?->value);
        self::assertSame(Outcome::DENIED, $snapshot->outcome);
        self::assertSame('rate_limited', $snapshot->reason);
        self::assertTrue($record->isActorSettled());
        self::assertNull($snapshot->actor);
        self::assertNull($snapshot->subject);
        self::assertSame('ada@example.test', $snapshot->identifier);
        self::assertSame([], $snapshot->properties ?? []);
        self::assertSame('api', $snapshot->guard);
    }

    /**
     * Rows of `[flow]` of every refusal but a sign-in's.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow}>
     */
    public static function provideOtherFlows(): iterable
    {
        foreach (self::provideFlows() as $name => [$flow]) {

            if ($flow === AuthenticationFlow::SIGN_IN) {
                continue;
            }

            yield $name => [$flow];
        }
    }

    /**
     * Only a sign-in out of attempts is a lockout.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @return void
     */
    #[DataProvider('provideOtherFlows')]
    public function testOnlyASignInOutOfAttemptsIsALockout(AuthenticationFlow $flow): void
    {
        $snapshot = self::snapshotOf(new AuthenticationFailed(self::context(), $flow, FailureReason::RATE_LIMITED, null, 30));

        self::assertNotSame(CapturedActivity::LOCKED_OUT->value, $snapshot->code?->value);
        self::assertSame([Outcome::FAILURE, 'rate_limited'], [$snapshot->outcome, $snapshot->reason]);
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
    }

    /**
     * A sign-in refused by the account's own limit is no lockout.
     *
     * @return void
     */
    public function testAnAccountsOwnLimitIsNoLockout(): void
    {
        $snapshot = self::snapshotOf(new AuthenticationFailed(self::context(), AuthenticationFlow::SIGN_IN, FailureReason::ACCOUNT_RATE_LIMITED, 'ada@example.test', 30));

        self::assertSame(AuthenticationActivity::SIGN_IN_FAILED_CONCEALED->value, $snapshot->code?->value);
        self::assertSame([Outcome::FAILURE, 'account_rate_limited'], [$snapshot->outcome, $snapshot->reason]);
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
    }

    /**
     * Rows of `[reason]` `laravel-authentication` conceals from the client.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideConcealedReasons(): iterable
    {
        foreach (FailureReason::cases() as $reason) {
            if (!$reason->isConcealed()) {
                continue;
            }

            yield $reason->value => [$reason];
        }
    }

    /**
     * A concealed sign-in refusal keeps its reason concealed.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideConcealedReasons')]
    public function testAConcealedSignInRefusalKeepsItsReasonConcealed(FailureReason $reason): void
    {
        $snapshot = self::snapshotOf(new AuthenticationFailed(self::context(), AuthenticationFlow::SIGN_IN, $reason));

        self::assertSame(AuthenticationActivity::SIGN_IN_FAILED_CONCEALED->value, $snapshot->code?->value);
        self::assertSame($reason->value, $snapshot->reason);
        self::assertSame(['method' => 'password', 'concealed' => true], $snapshot->properties);
    }

    /**
     * A concealed reason of another flow is concealed under that flow's code.
     *
     * @return void
     */
    public function testAConcealedRefusalOfAnotherFlowIsConcealed(): void
    {
        $snapshot = self::snapshotOf(new AuthenticationFailed(self::context(), AuthenticationFlow::PASSWORD_RESET, FailureReason::LINK_EXPIRED));

        self::assertSame(AuthenticationActivity::PASSWORD_RESET_FAILED->value, $snapshot->code?->value);
        self::assertTrue(($snapshot->properties ?? [])['concealed'] ?? false);
    }

    /**
     * An empty identifier is no identifier.
     *
     * @return void
     */
    public function testAnEmptyIdentifierIsNone(): void
    {
        self::assertNull(self::snapshotOf(new AuthenticationFailed(self::context(), AuthenticationFlow::SIGN_IN, FailureReason::INVALID_CREDENTIALS, ''))->identifier);
    }

    /**
     * A refusal's challenge is correlated by whose challenge it is.
     *
     * @return void
     */
    public function testARefusalsChallengeIsCorrelatedByWhoseItIs(): void
    {
        $factor = self::snapshotOf(new AuthenticationFailed(self::context(), AuthenticationFlow::FACTOR_CODE, FailureReason::INVALID_CREDENTIALS, challengeId: self::CHALLENGE));
        $signIn = self::snapshotOf(new AuthenticationFailed(self::context(), AuthenticationFlow::SIGN_IN, FailureReason::INVALID_CREDENTIALS, challengeId: self::CHALLENGE));

        self::assertSame('mfa:' . self::CHALLENGE, $factor->correlationId);
        self::assertSame('authentication:' . self::CHALLENGE, $signIn->correlationId);
    }

    /**
     * An event naming its connection and request is the SSO sign-in's.
     *
     * @return void
     */
    public function testARedemptionsEventsAreCorrelatedAsTheSsoSignIn(): void
    {
        $context  = self::context(connectionId: self::CONNECTION, requestReference: self::REFERENCE);
        $redeemed = self::snapshotOf(new ExternalResultRedeemed($context, AuthenticationFlow::REAUTHENTICATION));
        $refused  = self::snapshotOf(new AuthenticationFailed($context, AuthenticationFlow::SIGN_IN, FailureReason::LINK_MISMATCH, challengeId: self::CHALLENGE));

        self::assertSame(Correlation::ssoSignIn(self::CONNECTION, self::REFERENCE), $redeemed->correlationId);
        self::assertSame(Correlation::ssoSignIn(self::CONNECTION, self::REFERENCE), $refused->correlationId);
        self::assertSame(['method' => 'password', 'flow' => 'reauthentication', 'connection_id' => self::CONNECTION], $redeemed->properties);
    }

    /**
     * An event naming no session, connection or challenge is uncorrelated.
     *
     * @return void
     */
    public function testAnEventWithNothingToCorrelateHasNoCorrelation(): void
    {
        self::assertNull(self::snapshotOf(new PasskeyAdded(self::context(sessionId: null)))->correlationId);
    }

    /**
     * The identity's own action is the identity's, from the event.
     *
     * @return void
     */
    public function testTheIdentitysOwnActionIsAttributedFromTheEvent(): void
    {
        $record   = new PendingRecord;
        $snapshot = (new AuthenticationEventMapper)->map(new SessionCreated(self::context()), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->actor?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->principal?->toArray());
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => self::TENANT], $snapshot->tenant?->toArray());
        self::assertSame('api', $snapshot->guard);
        self::assertSame(self::SESSION, $snapshot->sessionId);
        self::assertSame(['192.0.2.10', 'iam-tests'], [$snapshot->ip, $snapshot->userAgent]);
        self::assertSame(['method' => 'password'], $snapshot->properties);
    }

    /**
     * The types are read through the morph map.
     *
     * @return void
     */
    public function testTheTypesAreReadThroughTheMorphMap(): void
    {
        Relation::morphMap(['person' => Person::class]);

        $snapshot = self::snapshotOf(new PrincipalSwitched(self::context(), Person::class, '6', 'tenant-8', true, false));

        self::assertSame('person', $snapshot->actor?->type);
        self::assertSame('person', $snapshot->principal?->type);
        self::assertSame(
            ['previous_principal_type' => 'person', 'previous_principal_id' => '6', 'previous_tenant_id' => 'tenant-8', 'principal_changed' => true, 'tenant_changed' => false],
            $snapshot->properties,
        );
    }

    /**
     * An event naming no principal or tenant names explicitly none.
     *
     * @return void
     */
    public function testAnEventNamingNoPrincipalOrTenantNamesNone(): void
    {
        $context = new EventContext('api', new ClientContext(null, null), self::person(), sessionId: self::SESSION);
        $record  = new PendingRecord;

        (new AuthenticationEventMapper)->map(new SessionCreated($context), $record);

        $record->fillPrincipal(References::of(Person::class, '99'));
        $record->fillTenant(References::tenant('elsewhere'));

        $snapshot = $record->snapshot();

        self::assertNull($snapshot->principal);
        self::assertNull($snapshot->tenant);
        self::assertNull($snapshot->ip);
    }

    /**
     * Rows of `[event]` whose actor is left to the contributors.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent}>
     */
    public static function provideCallersActions(): iterable
    {
        $context = self::context();

        yield 'a revocation' => [new SessionRevoked($context, RevocationReason::IDENTITY_DEACTIVATED)];

        yield 'a sign-out everywhere' => [new SignedOutEverywhere($context, RevocationReason::PASSWORD_CHANGED, 2, null)];

        yield 'a return to pending after a factor change' => [
            new SessionReturnedToPending($context, ['additional_factor'], CarbonImmutable::now(), AuthenticationFlow::FACTOR_CHANGE),
        ];

        yield 'a passkey removed' => [new PasskeyRemoved($context)];

        yield 'an API key issued' => [new ApiKeyIssued($context)];

        yield 'an API key revoked' => [new ApiKeyRevoked($context)];

        yield 'an API key rotated' => [new ApiKeyRotated($context, 'key-0')];
    }

    /**
     * What the member does not attribute is left to the contributors.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return void
     */
    #[DataProvider('provideCallersActions')]
    public function testWhatTheMemberDoesNotAttributeIsTheCallers(AuthenticationEvent $event): void
    {
        $record   = new PendingRecord;
        $snapshot = (new AuthenticationEventMapper)->map($event, $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertFalse($record->isActorSettled());
        self::assertNull($snapshot->actor);
        self::assertNull($snapshot->principal);
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => self::TENANT], $snapshot->tenant?->toArray());

        $record->fillPrincipal(References::of(Person::class, '1'));

        self::assertSame('1', $record->snapshot()->principal?->id);
    }

    /**
     * Rows of `[event]` by no one: a detected replay and an unlinked result.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent}>
     */
    public static function provideActionsOfNoOne(): iterable
    {
        yield 'a replay' => [new SessionRevoked(self::context(), RevocationReason::ROTATION_REUSE)];

        yield 'an unlinked result' => [new ExternalResultUnlinked(self::context(), 'https://idp.example.test')];
    }

    /**
     * What no one did is explicitly by no one.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return void
     */
    #[DataProvider('provideActionsOfNoOne')]
    public function testWhatNoOneDidIsByNoOne(AuthenticationEvent $event): void
    {
        $record = new PendingRecord;

        (new AuthenticationEventMapper)->map($event, $record);

        self::assertTrue($record->isActorSettled());
        self::assertNull($record->snapshot()->actor);
    }

    /**
     * Rows of `[event]` that are the identity's own.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent}>
     */
    public static function provideOwnActions(): iterable
    {
        yield 'a sign-out' => [new SessionRevoked(self::context(), RevocationReason::SIGNED_OUT)];

        yield 'a superseded session' => [new SessionRevoked(self::context(), RevocationReason::SUPERSEDED)];

        yield 'a switch\'s return to pending' => [new SessionReturnedToPending(self::context(), [], CarbonImmutable::now(), AuthenticationFlow::SWITCH)];

        yield 'a refresh\'s return to pending' => [new SessionReturnedToPending(self::context(), ['additional_factor'], CarbonImmutable::now(), AuthenticationFlow::REFRESH)];
    }

    /**
     * The identity's own action is by the identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return void
     */
    #[DataProvider('provideOwnActions')]
    public function testTheIdentitysOwnActionIsTheIdentitys(AuthenticationEvent $event): void
    {
        self::assertSame('7', self::snapshotOf($event)->actor?->id);
    }

    /**
     * Rows of `[event, properties]` of what each event keeps of itself.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent, 1: array<string, mixed>}>
     */
    public static function provideProperties(): iterable
    {
        $context = self::context(credentialId: 'key-1', scopes: ['read']);
        $later   = CarbonImmutable::parse('2026-11-07 12:00:00');
        $iso     = '2026-11-07T12:00:00.000000Z';

        yield 'a sign-in, which audit-log\'s code keeps none of' => [new SignedIn($context, false), []];

        yield 'a pending session' => [
            new SessionPending($context, ['additional_factor'], $later),
            ['method' => 'password', 'requires' => ['additional_factor'], 'expires_at' => $iso],
        ];

        yield 'a return to pending' => [
            new SessionReturnedToPending($context, ['choice'], $later, AuthenticationFlow::SWITCH, Person::class, '6', 'tenant-8'),
            [
                'method'                  => 'password',
                'flow'                    => 'switch',
                'requires'                => ['choice'],
                'expires_at'              => $iso,
                'previous_principal_type' => Person::class,
                'previous_principal_id'   => '6',
                'previous_tenant_id'      => 'tenant-8',
            ],
        ];

        yield 'a return to pending that left nothing' => [
            new SessionReturnedToPending($context, ['choice'], $later, AuthenticationFlow::SWITCH),
            ['method' => 'password', 'flow' => 'switch', 'requires' => ['choice'], 'expires_at' => $iso],
        ];

        yield 'a revocation' => [
            new SessionRevoked($context, RevocationReason::FACTOR_RESET),
            ['method' => 'password', 'reason' => 'factor_reset', 'session_principal_type' => Person::class, 'session_principal_id' => '7'],
        ];

        yield 'a user\'s own sign-out, which audit-log\'s code keeps none of' => [new SessionRevoked($context, RevocationReason::SIGNED_OUT), []];

        yield 'a session its own sign-in replaced' => [new SessionRevoked($context, RevocationReason::SUPERSEDED), ['method' => 'password', 'reason' => 'superseded']];

        yield 'a return to pending after a factor change' => [
            new SessionReturnedToPending($context, ['additional_factor'], $later, AuthenticationFlow::FACTOR_CHANGE),
            [
                'method'                 => 'password',
                'flow'                   => 'factor_change',
                'requires'               => ['additional_factor'],
                'expires_at'             => $iso,
                'session_principal_type' => Person::class,
                'session_principal_id'   => '7',
            ],
        ];

        yield 'a sign-out everywhere' => [
            new SignedOutEverywhere($context, RevocationReason::SIGNED_OUT_EVERYWHERE, 3, $later),
            ['reason' => 'signed_out_everywhere', 'revoked' => 3, 'tokens_valid_after' => $iso, 'scope_principal_type' => Person::class, 'scope_principal_id' => '7'],
        ];

        yield 'an identity\'s sign-out everywhere, which names no principal scope' => [
            new SignedOutEverywhere(self::context(principal: null), RevocationReason::SIGNED_OUT_EVERYWHERE, 3, null),
            ['reason' => 'signed_out_everywhere', 'revoked' => 3],
        ];

        yield 'a step-up' => [new SteppedUp($context, ProofKind::RECOVERY_CODE), ['method' => 'password', 'kind' => 'recovery_code']];

        yield 'an unlinked result' => [
            new ExternalResultUnlinked(self::context(connectionId: self::CONNECTION), 'https://idp.example.test'),
            ['method' => 'password', 'connection_id' => self::CONNECTION, 'issuer' => 'https://idp.example.test'],
        ];

        yield 'an identifier change requested' => [
            new IdentifierChangeRequested($context, 'email', 'new@example.test', $later),
            ['type' => 'email', 'identifier' => 'new@example.test', 'expires_at' => $iso],
        ];

        yield 'an identifier changed' => [
            new IdentifierChanged($context, 'email', 'old@example.test', 'new@example.test', $later),
            ['type' => 'email', 'previous' => 'old@example.test', 'identifier' => 'new@example.test'],
        ];

        yield 'a phone number verified' => [new IdentifierVerified($context, 'phone'), ['type' => 'phone']];

        yield 'a password changed' => [new PasswordSet($context, PasswordFlow::CHANGE), ['method' => 'password']];

        yield 'a passkey added' => [new PasskeyAdded($context), ['method' => 'password', 'passkey_id' => 'key-1']];

        yield 'a passkey removed' => [new PasskeyRemoved($context), ['method' => 'password', 'passkey_id' => 'key-1']];

        yield 'a passkey used' => [new PasskeyUsed($context), ['method' => 'password']];

        yield 'an API key issued' => [new ApiKeyIssued($context), ['scopes' => ['read'], 'key_id' => 'key-1', 'key_principal_type' => Person::class, 'key_principal_id' => '7']];

        yield 'an API key revoked' => [new ApiKeyRevoked($context), ['scopes' => ['read'], 'key_id' => 'key-1', 'key_principal_type' => Person::class, 'key_principal_id' => '7']];

        yield 'an API key rotated' => [
            new ApiKeyRotated($context, 'key-0'),
            ['scopes' => ['read'], 'previous_key_id' => 'key-0', 'key_id' => 'key-1', 'key_principal_type' => Person::class, 'key_principal_id' => '7'],
        ];

        yield 'an API key managed with no id' => [new ApiKeyIssued(self::context(credentialId: '')), ['key_principal_type' => Person::class, 'key_principal_id' => '7']];

        yield 'client credentials granted' => [new ClientCredentialsGranted($context), ['scopes' => ['read']]];

        yield 'a reauthentication' => [new Reauthenticated($context), ['method' => 'password']];
    }

    /**
     * Each event keeps exactly what its code's definition keeps.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @param  array<string, mixed>  $properties
     * @return void
     */
    #[DataProvider('provideProperties')]
    public function testEachEventKeepsWhatItsCodeKeeps(AuthenticationEvent $event, array $properties): void
    {
        self::assertSame($properties, self::snapshotOf($event)->properties ?? []);
    }

    /**
     * Rows of `[event]` whose credential is the one the activity used.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent}>
     */
    public static function provideCredentialsUsed(): iterable
    {
        $context = self::context(credentialId: 'key-1');

        yield 'a passkey used' => [new PasskeyUsed($context)];

        yield 'client credentials granted' => [new ClientCredentialsGranted($context)];

        foreach ([AuthenticationFlow::API_KEY, AuthenticationFlow::BEARER, AuthenticationFlow::CLIENT_CREDENTIALS] as $flow) {
            yield 'a refusal of the ' . $flow->value . ' flow' => [new AuthenticationFailed($context, $flow, FailureReason::INVALID_CREDENTIALS)];
        }
    }

    /**
     * The credential the activity used is the record's.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return void
     */
    #[DataProvider('provideCredentialsUsed')]
    public function testTheCredentialUsedIsTheRecords(AuthenticationEvent $event): void
    {
        self::assertSame('key-1', self::snapshotOf($event)->credentialId);
    }

    /**
     * A context naming an empty credential names none.
     *
     * @return void
     */
    public function testAnEmptyCredentialIsNone(): void
    {
        self::assertNull(self::snapshotOf(new PasskeyUsed(self::context(credentialId: '')))->credentialId);
    }

    /**
     * Rows of `[event, property]` managing a credential.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent, 1: string}>
     */
    public static function provideCredentialsManaged(): iterable
    {
        $context = self::context(credentialId: 'key-1');

        yield 'a passkey added' => [new PasskeyAdded($context), 'passkey_id'];

        yield 'a passkey removed' => [new PasskeyRemoved($context), 'passkey_id'];

        yield 'an API key issued' => [new ApiKeyIssued($context), 'key_id'];

        yield 'an API key revoked' => [new ApiKeyRevoked($context), 'key_id'];

        yield 'an API key rotated' => [new ApiKeyRotated($context, 'key-0'), 'key_id'];
    }

    /**
     * A credential an event manages is never the record's credential.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @param  string  $property
     * @return void
     */
    #[DataProvider('provideCredentialsManaged')]
    public function testACredentialManagedIsNeverTheRecords(AuthenticationEvent $event, string $property): void
    {
        $snapshot = self::snapshotOf($event);

        self::assertNull($snapshot->credentialId);
        self::assertSame('key-1', $snapshot->properties[$property] ?? null);
    }

    /**
     * Rows of `[event, prefix]` naming the principal acted on.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent, 1: string}>
     */
    public static function providePrincipalsActedOn(): iterable
    {
        $context = self::context(principal: self::person(6));

        yield 'a principal\'s sessions ended' => [new SignedOutEverywhere($context, RevocationReason::REVOKED, 2, null), 'scope'];

        yield 'an API key issued' => [new ApiKeyIssued($context), 'key'];

        yield 'an API key revoked' => [new ApiKeyRevoked($context), 'key'];

        yield 'an API key rotated' => [new ApiKeyRotated($context, 'key-0'), 'key'];

        yield 'a revocation' => [new SessionRevoked($context, RevocationReason::REVOKED), 'session'];

        yield 'a return to pending after a factor change' => [
            new SessionReturnedToPending($context, ['additional_factor'], CarbonImmutable::now(), AuthenticationFlow::FACTOR_CHANGE),
            'session',
        ];
    }

    /**
     * A record left to the caller keeps the principal acted on.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @param  string  $prefix
     * @return void
     */
    #[DataProvider('providePrincipalsActedOn')]
    public function testARecordLeftToTheCallerKeepsThePrincipalActedOn(AuthenticationEvent $event, string $prefix): void
    {
        Relation::morphMap(['person' => Person::class]);

        $record = (new AuthenticationEventMapper)->map($event, new PendingRecord) ?? self::fail('The event was skipped.');

        $record->fillActor(References::of('admin', '99'));
        $record->fillPrincipal(References::of('admin', '99'));
        $record->fillTenant(References::tenant('elsewhere'));

        $snapshot = $record->snapshot();

        self::assertSame(['type' => 'admin', 'id' => '99'], $snapshot->principal?->toArray());
        self::assertSame(['type' => 'person', 'id' => '7'], $snapshot->subject?->toArray());
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => self::TENANT], $snapshot->tenant?->toArray());
        self::assertSame('person', $snapshot->properties[$prefix . '_principal_type'] ?? null);
        self::assertSame('6', $snapshot->properties[$prefix . '_principal_id'] ?? null);
    }

    /**
     * A record of the identity's own action keeps no principal it acted on.
     *
     * @return void
     */
    public function testAnOwnActionKeepsNoPrincipalActedOn(): void
    {
        $snapshot = self::snapshotOf(new SessionRevoked(self::context(principal: self::person(6)), RevocationReason::SUPERSEDED));

        self::assertSame('6', $snapshot->principal?->id);
        self::assertSame(['method' => 'password', 'reason' => 'superseded'], $snapshot->properties);
    }

    /**
     * The snapshot of the record the mapper describes the event on.
     *
     * @param  object  $event
     * @return \SineMacula\Laravel\AuditLog\Records\PendingSnapshot
     */
    private static function snapshotOf(object $event): PendingSnapshot
    {
        $record = (new AuthenticationEventMapper)->map($event, new PendingRecord);

        self::assertInstanceOf(PendingRecord::class, $record);

        return $record->snapshot();
    }

    /**
     * A password sign-in context for the person in the tenant.
     *
     * @param  ?string  $sessionId
     * @param  ?string  $credentialId
     * @param  ?list<string>  $scopes
     * @param  ?string  $connectionId
     * @param  ?string  $requestReference
     * @param  false|\Tests\Fixtures\Models\Person|null  $principal
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function context(
        ?string $sessionId = self::SESSION,
        ?string $credentialId = null,
        ?array $scopes = null,
        ?string $connectionId = null,
        ?string $requestReference = null,
        false|Person|null $principal = false,
    ): EventContext {
        $person = self::person();

        return new EventContext(
            'api',
            new ClientContext('192.0.2.10', 'iam-tests'),
            $person,
            $principal === false ? $person : $principal,
            new ClaimedTenant(self::TENANT),
            null,
            'password',
            $sessionId,
            credentialId: $credentialId,
            scopes: $scopes,
            connectionId: $connectionId,
            requestReference: $requestReference,
        );
    }

    /**
     * The person every event is about, or another.
     *
     * @param  int  $id
     * @return \Tests\Fixtures\Models\Person
     */
    private static function person(int $id = 7): Person
    {
        return (new Person)->forceFill(['id' => $id]);
    }
}
