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
use SineMacula\Laravel\Iam\Audit\Enums\SsoActivity;
use SineMacula\Laravel\Iam\Audit\Mappers\Snapshot;
use SineMacula\Laravel\Iam\Audit\Mappers\SsoEventMapper;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\ConnectionEnabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\DomainClaimed;
use SineMacula\Laravel\Sso\Events\DomainLapsed;
use SineMacula\Laravel\Sso\Events\DomainRecheckFailed;
use SineMacula\Laravel\Sso\Events\DomainRemoved;
use SineMacula\Laravel\Sso\Events\DomainRestored;
use SineMacula\Laravel\Sso\Events\DomainVerified;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\JwksRefreshed;
use SineMacula\Laravel\Sso\Events\JwksRefreshFailed;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyMadeCurrent;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Events\LinkActivated;
use SineMacula\Laravel\Sso\Events\LinkConfirmed;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Events\MetadataRefreshed;
use SineMacula\Laravel\Sso\Events\MetadataRefreshFailed;
use SineMacula\Laravel\Sso\Events\ReauthenticationCompleted;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Events\UnsolicitedResponseReinitiated;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Fixtures\Models\Person;

/**
 * Tests the mapper of SSO's events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoEventMapper::class)]
#[CoversClass(Snapshot::class)]
final class SsoEventMapperTest extends TestCase
{
    /** @var string The connection every event concerns. */
    private const string CONNECTION = '01JC0000000000000000000000';

    /** @var string The request a flow's events answer. */
    private const string REFERENCE = 'reference-1';

    /** @var string The domain a domain's events concern. */
    private const string DOMAIN = '01JD0000000000000000000000';

    /** @var string The instant every dated field holds. */
    private const string NOON = '2026-11-07 12:00:00';

    /** @var list<string> The codes of events about a connection. */
    private const array CONNECTIONS = [
        'sso.connection_created', 'sso.connection_updated', 'sso.connection_enabled', 'sso.connection_disabled', 'sso.connection_deleted',
        'sso.key_added', 'sso.key_made_current', 'sso.key_retired', 'sso.key_nearing_expiry',
        'sso.metadata_refreshed', 'sso.metadata_refresh_failed', 'sso.jwks_refreshed', 'sso.jwks_refresh_failed',
    ];

    /** @var list<string> The codes of events explicitly by no one. */
    private const array NOBODY = [
        'sso.flow_failed', 'sso.link_suspended', 'sso.domain_recheck_failed', 'sso.domain_restored', 'sso.domain_lapsed',
        'sso.key_nearing_expiry', 'sso.metadata_refresh_failed', 'sso.jwks_refreshed', 'sso.jwks_refresh_failed',
    ];

    /** @var list<string> The codes of events whose actor is left to the contributors. */
    private const array CALLERS = [
        'sso.link_removed', 'sso.connection_created', 'sso.connection_updated', 'sso.connection_enabled', 'sso.connection_disabled',
        'sso.connection_deleted', 'sso.domain_claimed', 'sso.domain_verified', 'sso.domain_removed', 'sso.enforcement_changed',
        'sso.key_added', 'sso.key_made_current', 'sso.key_retired', 'sso.metadata_refreshed',
    ];

    /** @var string The instant as a record keeps it. */
    private const string NOON_ISO = '2026-11-07T12:00:00.000000Z';

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
     * Every one of SSO's events is provided for.
     *
     * @return void
     */
    public function testEveryEventIsProvidedFor(): void
    {
        $codes = array_map(static fn (array $row): string => $row[1]->value, iterator_to_array(self::provideEvents(), false));

        self::assertEqualsCanonicalizing(array_map(static fn (SsoActivity $code): string => $code->value, SsoActivity::cases()), $codes);
    }

    /**
     * Rows of `[event, code, details]` for every one of SSO's events.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Contracts\SsoEvent, 1: \SineMacula\Laravel\Iam\Audit\Enums\SsoActivity, 2: array<string, mixed>}>
     */
    public static function provideEvents(): iterable
    {
        $flow   = self::flowContext();
        $admin  = self::adminContext();
        $noon   = CarbonImmutable::parse(self::NOON);
        $domain = ['domain_id' => self::DOMAIN, 'domain' => 'example.test'];
        $key    = ['key_id' => 'key-1', 'use' => 'sp_signing', 'fingerprint' => 'ab12'];
        $flowed = ['application' => 'api', 'purpose' => 'sign_in', 'method' => 'external_provider'];

        yield 'a flow started' => [new AuthorizationRequestStarted($flow), SsoActivity::AUTHORIZATION_REQUEST_STARTED, $flowed];

        yield 'a result verified' => [new ResultVerified($flow), SsoActivity::RESULT_VERIFIED, $flowed];

        yield 'a result unlinked' => [self::unlinked($flow), SsoActivity::RESULT_UNLINKED, $flowed];

        yield 'a handoff issued' => [new HandoffIssued($flow), SsoActivity::HANDOFF_ISSUED, $flowed];

        yield 'a handoff redeemed' => [new HandoffRedeemed($flow), SsoActivity::HANDOFF_REDEEMED, $flowed];

        yield 'a reauthentication completed' => [new ReauthenticationCompleted($flow), SsoActivity::REAUTHENTICATION_COMPLETED, $flowed];

        yield 'a flow failed' => [new FlowFailed($flow, Flow::REDEMPTION, FailureReason::REPLAYED), SsoActivity::FLOW_FAILED, [...$flowed, 'flow' => 'redemption']];

        yield 'an unsolicited response reinitiated' => [new UnsolicitedResponseReinitiated($flow), SsoActivity::UNSOLICITED_RESPONSE_REINITIATED, $flowed];

        yield 'a link created' => [new LinkCreated($flow, LinkOrigin::VERIFIED_DOMAIN), SsoActivity::LINK_CREATED, [...$flowed, 'origin' => 'verified_domain']];

        yield 'a link removed' => [new LinkRemoved($flow), SsoActivity::LINK_REMOVED, $flowed];

        yield 'a link activated' => [new LinkActivated('link-1', $flow), SsoActivity::LINK_ACTIVATED, [...$flowed, 'link_id' => 'link-1']];

        yield 'a link confirmed' => [new LinkConfirmed($flow), SsoActivity::LINK_CONFIRMED, $flowed];

        yield 'a link suspended' => [new LinkSuspended($flow), SsoActivity::LINK_SUSPENDED, $flowed];

        yield 'a connection created' => [new ConnectionCreated($admin), SsoActivity::CONNECTION_CREATED, []];

        yield 'a connection updated' => [new ConnectionUpdated($admin, ['client_id']), SsoActivity::CONNECTION_UPDATED, ['changed_settings' => ['client_id']]];

        yield 'a connection enabled' => [new ConnectionEnabled($admin), SsoActivity::CONNECTION_ENABLED, []];

        yield 'a connection disabled' => [new ConnectionDisabled($admin), SsoActivity::CONNECTION_DISABLED, []];

        yield 'a connection deleted' => [new ConnectionDeleted($admin), SsoActivity::CONNECTION_DELETED, []];

        yield 'a domain claimed' => [
            new DomainClaimed($admin, self::DOMAIN, 'example.test', '_sso.example.test', $noon),
            SsoActivity::DOMAIN_CLAIMED,
            [...$domain, 'record_name' => '_sso.example.test', 'pending_expires_at' => self::NOON_ISO],
        ];

        yield 'a domain verified' => [new DomainVerified($admin, self::DOMAIN, 'example.test', $noon), SsoActivity::DOMAIN_VERIFIED, [...$domain, 'verified_at' => self::NOON_ISO]];

        yield 'a domain recheck failed' => [
            new DomainRecheckFailed($admin, self::DOMAIN, 'example.test', RecheckFailure::RECORD_ABSENT, $noon),
            SsoActivity::DOMAIN_RECHECK_FAILED,
            [...$domain, 'lapses_at' => self::NOON_ISO],
        ];

        yield 'a domain restored' => [
            new DomainRestored($admin, self::DOMAIN, 'example.test', $noon, $noon),
            SsoActivity::DOMAIN_RESTORED,
            [...$domain, 'verified_at' => self::NOON_ISO, 'checked_at' => self::NOON_ISO],
        ];

        yield 'a domain lapsed' => [new DomainLapsed($admin, self::DOMAIN, 'example.test'), SsoActivity::DOMAIN_LAPSED, $domain];

        yield 'a domain removed' => [
            new DomainRemoved($admin, self::DOMAIN, 'example.test', DomainState::VERIFIED),
            SsoActivity::DOMAIN_REMOVED,
            [...$domain, 'state' => 'verified'],
        ];

        yield 'an enforcement changed' => [
            new EnforcementChanged($admin, true, [self::CONNECTION], 'v2', 'v1'),
            SsoActivity::ENFORCEMENT_CHANGED,
            ['enabled' => true, 'connection_ids' => [self::CONNECTION], 'version' => 'v2', 'previous_version' => 'v1'],
        ];

        yield 'an exemption used' => [
            new ExemptionUsed($flow, 'v2'),
            SsoActivity::EXEMPTION_USED,
            ['application' => 'api', 'method' => 'external_provider', 'enforcement_version' => 'v2'],
        ];

        yield 'a key added' => [
            new KeyAdded($admin, 'key-1', KeyUse::SP_SIGNING, KeyState::NEXT, 'ab12', $noon),
            SsoActivity::KEY_ADDED,
            [...$key, 'state' => 'next', 'not_after' => self::NOON_ISO],
        ];

        yield 'a key made current' => [
            new KeyMadeCurrent($admin, 'key-1', KeyUse::SP_SIGNING, 'ab12', 'key-0'),
            SsoActivity::KEY_MADE_CURRENT,
            [...$key, 'previous_key_id' => 'key-0'],
        ];

        yield 'a key retired' => [new KeyRetired($admin, 'key-1', KeyUse::SP_SIGNING, 'ab12'), SsoActivity::KEY_RETIRED, $key];

        yield 'a key nearing expiry' => [
            new KeyNearingExpiry($admin, 'key-1', KeyUse::SP_SIGNING, 'ab12', $noon, 14),
            SsoActivity::KEY_NEARING_EXPIRY,
            [...$key, 'not_after' => self::NOON_ISO, 'threshold_days' => 14],
        ];

        yield 'metadata refreshed' => [
            new MetadataRefreshed($admin, ['sso_url'], 4, true),
            SsoActivity::METADATA_REFRESHED,
            ['changed_settings' => ['sso_url'], 'metadata_version' => 4, 'trust_changed' => true],
        ];

        yield 'a metadata refresh failed' => [
            new MetadataRefreshFailed($admin, FailureReason::FETCH_FAILED, 2, $noon),
            SsoActivity::METADATA_REFRESH_FAILED,
            ['failures' => 2, 'next_attempt_at' => self::NOON_ISO],
        ];

        yield 'JWKS refreshed' => [
            new JwksRefreshed($admin, 5, 1, 1, false),
            SsoActivity::JWKS_REFRESHED,
            ['jwks_version' => 5, 'keys_added' => 1, 'keys_removed' => 1, 'trust_changed' => false],
        ];

        yield 'a JWKS refresh failed' => [
            new JwksRefreshFailed($admin, FailureReason::FETCH_FAILED, $noon),
            SsoActivity::JWKS_REFRESH_FAILED,
            ['next_refetch_at' => self::NOON_ISO],
        ];
    }

    /**
     * Each event is recorded under its code, keeping what its code keeps.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  \SineMacula\Laravel\Iam\Audit\Enums\SsoActivity  $code
     * @param  array<string, mixed>  $details
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEachEventIsRecordedUnderItsCode(SsoEvent $event, SsoActivity $code, array $details): void
    {
        $snapshot   = self::snapshotOf($event);
        $connection = ['connection_id' => self::CONNECTION, 'connection_tenant_id' => 'tenant-1', 'protocol' => 'oidc'];
        $kept       = array_intersect_key([...$connection, ...$details], array_flip($code->properties()));

        self::assertSame($code->value, $snapshot->code?->value);
        self::assertSame($kept, $snapshot->properties ?? []);
        self::assertSame($details, array_diff_key($kept, $connection));
    }

    /**
     * Rows of `[event, code]` for every one of SSO's events.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Contracts\SsoEvent, 1: \SineMacula\Laravel\Iam\Audit\Enums\SsoActivity}>
     */
    public static function provideCodedEvents(): iterable
    {
        foreach (self::provideEvents() as $name => [$event, $code]) {
            yield $name => [$event, $code];
        }
    }

    /**
     * Each event is about its subject and by whom it reports.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  \SineMacula\Laravel\Iam\Audit\Enums\SsoActivity  $code
     * @return void
     */
    #[DataProvider('provideCodedEvents')]
    public function testEachEventsSubjectAndActor(SsoEvent $event, SsoActivity $code): void
    {
        $record   = new PendingRecord;
        $snapshot = (new SsoEventMapper)->map($event, $record)?->snapshot();
        $value    = $code->value;

        $subject = match (true) {
            str_starts_with($value, 'sso.domain_')             => ['type' => Domain::class, 'id' => self::DOMAIN],
            $value === SsoActivity::ENFORCEMENT_CHANGED->value => null,
            in_array($value, self::CONNECTIONS, true)          => ['type' => Connection::class, 'id' => self::CONNECTION],
            default                                            => ['type' => Person::class, 'id' => '7'],
        };

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertSame($subject, $snapshot->subject?->toArray());
        self::assertSame(!in_array($value, self::CALLERS, true), $record->isActorSettled());
        self::assertSame(in_array($value, [...self::NOBODY, ...self::CALLERS], true) ? null : '7', $snapshot->actor?->id);
    }

    /**
     * An event that is not one of SSO's is skipped.
     *
     * @return void
     */
    public function testAnotherEventIsSkipped(): void
    {
        $other = new class implements SsoEvent {
            /**
             * An empty context.
             *
             * @return \SineMacula\Laravel\Sso\Events\EventContext
             */
            #[\Override]
            public function context(): EventContext
            {
                return new EventContext(CarbonImmutable::now());
            }
        };

        self::assertNull((new SsoEventMapper)->map($other, new PendingRecord));
        self::assertNull((new SsoEventMapper)->map(new \stdClass, new PendingRecord));
    }

    /**
     * A refusal or a failed refresh or recheck carries its reason.
     *
     * @return void
     */
    public function testTheOutcomeIsTheEvents(): void
    {
        $noon = CarbonImmutable::parse(self::NOON);

        $outcomes = array_map(static function (SsoEvent $event): array {
            $snapshot = self::snapshotOf($event);

            return [$snapshot->outcome, $snapshot->reason];
        }, [
            new FlowFailed(self::flowContext(), Flow::CALLBACK, FailureReason::NONCE_MISMATCH),
            new MetadataRefreshFailed(self::adminContext(), FailureReason::METADATA_INVALID, 1, null),
            new JwksRefreshFailed(self::adminContext(), FailureReason::JWKS_INVALID, null),
            new DomainRecheckFailed(self::adminContext(), self::DOMAIN, 'example.test', RecheckFailure::LOOKUP_FAILED, $noon),
            new ResultVerified(self::flowContext()),
        ]);

        self::assertSame([
            [Outcome::FAILURE, 'nonce_mismatch'],
            [Outcome::FAILURE, 'metadata_invalid'],
            [Outcome::FAILURE, 'jwks_invalid'],
            [Outcome::FAILURE, 'lookup_failed'],
            [Outcome::SUCCESS, null],
        ], $outcomes);
    }

    /**
     * A flow is the identity's, in the active tenant, correlated by sign-in.
     *
     * @return void
     */
    public function testAFlowIsAttributedToTheIdentity(): void
    {
        $record   = new PendingRecord;
        $snapshot = (new SsoEventMapper)->map(new HandoffRedeemed(self::flowContext()), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->actor?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->principal?->toArray());
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => 'tenant-2'], $snapshot->tenant?->toArray());
        self::assertSame('api', $snapshot->guard);
        self::assertSame('session-1', $snapshot->sessionId);
        self::assertSame(['192.0.2.10', 'iam-tests'], [$snapshot->ip, $snapshot->userAgent]);
        self::assertSame('sso:' . self::CONNECTION . ':' . self::REFERENCE, $snapshot->correlationId);
    }

    /**
     * Without a request an event is correlated by its session, if any.
     *
     * @return void
     */
    public function testWithoutARequestTheSessionCorrelates(): void
    {
        $exemption = self::snapshotOf(new ExemptionUsed(new EventContext(CarbonImmutable::now(), connectionId: self::CONNECTION, sessionId: 'session-1'), 'v1'));
        $created   = self::snapshotOf(new ConnectionCreated(self::adminContext()));

        self::assertSame('session:session-1', $exemption->correlationId);
        self::assertNull($created->correlationId);
    }

    /**
     * An administration event is the acting identity's, on the connection.
     *
     * @return void
     */
    public function testAnAdministrationEventIsTheActingIdentitysOnTheConnection(): void
    {
        Relation::morphMap(['sso_connection' => Connection::class, 'person' => Person::class]);

        $record   = new PendingRecord;
        $snapshot = (new SsoEventMapper)->map(new ConnectionEnabled(self::adminContext(Person::class, '1')), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertSame(['type' => 'person', 'id' => '1'], $snapshot->actor?->toArray());
        self::assertSame(['type' => 'sso_connection', 'id' => self::CONNECTION], $snapshot->subject?->toArray());
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => 'tenant-1'], $snapshot->tenant?->toArray());
        self::assertNull($snapshot->principal);
    }

    /**
     * A domain's event is about the domain, an enforcement change none.
     *
     * @return void
     */
    public function testADomainsAndAnEnforcementsSubjects(): void
    {
        $domain      = self::snapshotOf(new DomainLapsed(self::adminContext(), self::DOMAIN, 'example.test'));
        $enforcement = self::snapshotOf(new EnforcementChanged(self::flowContext(), false, [], 'v3', 'v2'));

        self::assertSame(['type' => Domain::class, 'id' => self::DOMAIN], $domain->subject?->toArray());
        self::assertNull($enforcement->subject);
        self::assertSame('tenant-2', $enforcement->tenant?->id);
    }

    /**
     * Rows of `[event]` that are by no one without an acting identity.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Contracts\SsoEvent}>
     */
    public static function provideActionsOfNoOne(): iterable
    {
        $noon = CarbonImmutable::parse(self::NOON);

        yield 'a refusal' => [new FlowFailed(self::flowContext(), Flow::ASSERTION, FailureReason::SIGNATURE_INVALID)];

        yield 'a link suspended' => [new LinkSuspended(self::flowContext())];

        yield 'a recheck failed' => [new DomainRecheckFailed(self::flowContext(), self::DOMAIN, 'example.test', RecheckFailure::RECORD_CHANGED, null)];

        yield 'a domain restored' => [new DomainRestored(self::flowContext(), self::DOMAIN, 'example.test', $noon, $noon)];

        yield 'a domain lapsed' => [new DomainLapsed(self::flowContext(), self::DOMAIN, 'example.test')];

        yield 'a key nearing expiry' => [new KeyNearingExpiry(self::flowContext(), 'key-1', KeyUse::SP_SIGNING, 'ab12', $noon, 7)];

        yield 'a metadata refresh failed' => [new MetadataRefreshFailed(self::flowContext(), FailureReason::FETCH_REFUSED, 1, null)];

        yield 'JWKS refreshed' => [new JwksRefreshed(self::flowContext(), 1, 0, 0, false)];

        yield 'a JWKS refresh failed' => [new JwksRefreshFailed(self::flowContext(), FailureReason::FETCH_REFUSED, null)];

        yield 'a flow started before anyone is known' => [new AuthorizationRequestStarted(new EventContext(CarbonImmutable::now(), connectionId: self::CONNECTION))];
    }

    /**
     * What no one did is by no one, with the event's principal and tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return void
     */
    #[DataProvider('provideActionsOfNoOne')]
    public function testWhatNoOneDidIsByNoOne(SsoEvent $event): void
    {
        $record = new PendingRecord;

        (new SsoEventMapper)->map($event, $record);

        self::assertTrue($record->isActorSettled());
        self::assertNull($record->snapshot()->actor);
    }

    /**
     * Rows of `[event]` an administration helper reports.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Contracts\SsoEvent}>
     */
    public static function provideAdministration(): iterable
    {
        $admin = self::adminContext();
        $noon  = CarbonImmutable::parse(self::NOON);

        yield 'a link removed' => [new LinkRemoved(self::flowContext())];

        yield 'a connection created' => [new ConnectionCreated($admin)];

        yield 'a connection updated' => [new ConnectionUpdated($admin, [])];

        yield 'a connection enabled' => [new ConnectionEnabled($admin)];

        yield 'a connection disabled' => [new ConnectionDisabled($admin)];

        yield 'a connection deleted' => [new ConnectionDeleted($admin)];

        yield 'a domain claimed' => [new DomainClaimed($admin, self::DOMAIN, 'example.test', '_sso.example.test', $noon)];

        yield 'a domain verified' => [new DomainVerified($admin, self::DOMAIN, 'example.test', $noon)];

        yield 'a domain removed' => [new DomainRemoved($admin, self::DOMAIN, 'example.test', DomainState::PENDING)];

        yield 'an enforcement changed' => [new EnforcementChanged($admin, true, [], 'v1', null)];

        yield 'a key added' => [new KeyAdded($admin, 'key-1', KeyUse::SP_SIGNING, null, 'ab12', null)];

        yield 'a key made current' => [new KeyMadeCurrent($admin, 'key-1', KeyUse::SP_SIGNING, 'ab12', null)];

        yield 'a key retired' => [new KeyRetired($admin, 'key-1', KeyUse::SP_SIGNING, 'ab12')];

        yield 'metadata refreshed' => [new MetadataRefreshed($admin, [], 1, false)];
    }

    /**
     * An administration helper's event with no acting identity is the caller's.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return void
     */
    #[DataProvider('provideAdministration')]
    public function testAnAdministrationEventWithNoActingIdentityIsTheCallers(SsoEvent $event): void
    {
        $record = new PendingRecord;

        (new SsoEventMapper)->map($event, $record);

        self::assertFalse($record->isActorSettled());
        self::assertNull($record->snapshot()->principal);
    }

    /**
     * A migration's link with no acting identity is the caller's.
     *
     * @return void
     */
    public function testAMigrationsLinkWithNoActingIdentityIsTheCallers(): void
    {
        $record   = new PendingRecord;
        $snapshot = (new SsoEventMapper)->map(new LinkCreated(self::migrationContext(), LinkOrigin::MIGRATION), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertFalse($record->isActorSettled());
        self::assertNull($snapshot->actor);
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
        self::assertNull($snapshot->principal);
        self::assertSame(['type' => References::TENANT_TYPE, 'id' => 'tenant-1'], $snapshot->tenant?->toArray());
    }

    /**
     * A migration's link with an acting identity is the operator's.
     *
     * @return void
     */
    public function testAMigrationsLinkWithAnActingIdentityIsTheOperators(): void
    {
        $record   = new PendingRecord;
        $snapshot = (new SsoEventMapper)->map(new LinkCreated(self::migrationContext(Person::class, '1'), LinkOrigin::MIGRATION), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertSame(['type' => Person::class, 'id' => '1'], $snapshot->actor?->toArray());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->subject?->toArray());
        self::assertNull($snapshot->principal);
    }

    /**
     * Rows of `[origin]` of a link the identity's own flow made.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin}>
     */
    public static function provideFlowOrigins(): iterable
    {
        foreach (LinkOrigin::cases() as $origin) {

            if ($origin === LinkOrigin::MIGRATION) {
                continue;
            }

            yield $origin->value => [$origin];
        }
    }

    /**
     * A link the identity's own flow made is the identity's.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @return void
     */
    #[DataProvider('provideFlowOrigins')]
    public function testALinkAFlowMadeIsTheIdentitys(LinkOrigin $origin): void
    {
        $record   = new PendingRecord;
        $snapshot = (new SsoEventMapper)->map(new LinkCreated(self::flowContext(), $origin), $record)?->snapshot();

        self::assertInstanceOf(PendingSnapshot::class, $snapshot);
        self::assertTrue($record->isActorSettled());
        self::assertSame(['type' => Person::class, 'id' => '7'], $snapshot->actor?->toArray());
    }

    /**
     * An unlinked result never records its provisioning grant.
     *
     * @return void
     */
    public function testAnUnlinkedResultNeverRecordsItsGrant(): void
    {
        $snapshot = self::snapshotOf(self::unlinked(self::flowContext()));

        self::assertStringNotContainsString('grant', (string) json_encode($snapshot->properties));
        self::assertStringNotContainsString('subject-1', (string) json_encode($snapshot->properties));
    }

    /**
     * The snapshot of the record the mapper describes the event on.
     *
     * @param  object  $event
     * @return \SineMacula\Laravel\AuditLog\Records\PendingSnapshot
     */
    private static function snapshotOf(object $event): PendingSnapshot
    {
        $record = (new SsoEventMapper)->map($event, new PendingRecord);

        self::assertInstanceOf(PendingRecord::class, $record);

        return $record->snapshot();
    }

    /**
     * A sign-in flow's context in a child tenant of the connection's.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private static function flowContext(): EventContext
    {
        return new EventContext(
            CarbonImmutable::now(),
            ip: '192.0.2.10',
            userAgent: 'iam-tests',
            connectionId: self::CONNECTION,
            connectionTenantId: 'tenant-1',
            protocol: 'oidc',
            application: 'api',
            purpose: 'sign_in',
            requestReference: self::REFERENCE,
            identityMorphClass: Person::class,
            identityId: '7',
            principalMorphClass: Person::class,
            principalId: '7',
            tenantId: 'tenant-2',
            sessionId: 'session-1',
            method: 'external_provider',
        );
    }

    /**
     * An administration helper's context with the acting identity given.
     *
     * @param  ?string  $actingType
     * @param  ?string  $actingId
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private static function adminContext(?string $actingType = null, ?string $actingId = null): EventContext
    {
        return new EventContext(
            CarbonImmutable::now(),
            connectionId: self::CONNECTION,
            connectionTenantId: 'tenant-1',
            protocol: 'oidc',
            actingIdentityMorphClass: $actingType,
            actingIdentityId: $actingId,
        );
    }

    /**
     * A subject migration's context with the acting identity given.
     *
     * @param  ?string  $actingType
     * @param  ?string  $actingId
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private static function migrationContext(?string $actingType = null, ?string $actingId = null): EventContext
    {
        return new EventContext(
            CarbonImmutable::now(),
            connectionId: self::CONNECTION,
            connectionTenantId: 'tenant-1',
            protocol: 'oidc',
            identityMorphClass: Person::class,
            identityId: '7',
            actingIdentityMorphClass: $actingType,
            actingIdentityId: $actingId,
        );
    }

    /**
     * An unlinked `sign_in` result's event, with a grant issued for it.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @return \SineMacula\Laravel\Sso\Events\ResultUnlinked
     */
    private static function unlinked(EventContext $context): ResultUnlinked
    {
        $result = new VerifiedResult(
            'https://idp.example.test',
            'subject-1',
            null,
            self::CONNECTION,
            'tenant-1',
            'oidc',
            'api',
            Purpose::SIGN_IN,
            RequestReference::fromString('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
            [],
            false,
            new AuthenticationContext(CarbonImmutable::now()->startOfSecond()),
        );

        return new ResultUnlinked($context, $result, ProvisioningGrant::issue($result, 'request-1', CarbonImmutable::now()->addMinute()));
    }
}
