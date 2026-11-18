<?php

declare(strict_types = 1);

namespace Tests\Integration\Audit;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthenticationEventMapper;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\TestCase;

/**
 * Integration tests for the records left when another member ends sessions.
 *
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationEventMapper::class)]
#[CoversClass(SessionRevocationAdapter::class)]
#[CoversClass(SessionRevokerAdapter::class)]
final class RevocationRecordsTest extends TestCase
{
    use ArrangesFactorChanges, MigratesSso, RunsSsoFlows, SignsInPeople, SignsInThroughLinks {
        SignsInThroughLinks::keyOf insteadof RunsSsoFlows;
        SignsInThroughLinks::referenceOf insteadof RunsSsoFlows;
        SignsInThroughLinks::signInMethods insteadof RunsSsoFlows;
    }

    /**
     * Let sessions act in any tenant.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);
    }

    /**
     * A disabled connection records each session it ends, by no one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADisabledConnectionRecordsEachSessionItEnds(): void
    {
        $this->arrangeSso();

        $person   = $this->createPerson();
        $sessions = [$this->inTenant($this->signInThrough($person, $this->connectionId)), $this->inTenant($this->signInThrough($person, $this->connectionId, 'link-2'))];
        $fake     = AuditLog::fake();

        self::assertTrue($this->app?->make(ConnectionLifecycle::class)->disable(self::TENANT, $this->connectionId, self::ssoClient())->isSucceeded());

        self::assertSame(self::expected($sessions, 'connection_disabled', $person, null), self::revocations($fake));
    }

    /**
     * A tenant's new sign-in rule records each session it ends, by no one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantPolicyChangeRecordsEachSessionItEnds(): void
    {
        $this->arrangeSso();

        Config::set('sso.features.enforcement', true);

        DB::table('sso_connections')->where('id', $this->connectionId)->update(['has_completed_sign_in' => true]);

        $person   = $this->createPerson();
        $sessions = [$this->inTenant($this->signIn($person)->record), $this->inTenant($this->signIn($person)->record)];
        $fake     = AuditLog::fake();

        // The sign-ins leave the person on the guard; no one makes the change.
        $this->app?->make('auth')->forgetGuards();

        $result = $this->app?->make(EnforcementService::class)->update(self::TENANT, true, [$this->connectionId], self::ssoClient());

        self::assertTrue($result?->isChanged());
        self::assertSame(self::expected($sessions, 'tenant_policy_changed', $person, null), self::revocations($fake));
    }

    /**
     * A removed factor records the other session it ends, by the caller.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovedFactorRecordsTheSessionItEnds(): void
    {
        $person  = $this->createPerson();
        $other   = $this->inTenant($this->signIn($person)->record);
        $current = $this->inTenant($this->signIn($person)->record);

        $this->actingOnSession($current, self::GUARD);

        [$removed, $kept] = [$this->confirmedFactor($person), $this->confirmedFactor($person)];

        $this->stepUpWith($person, $current, $kept->id);

        $fake   = AuditLog::fake();
        $result = Mfa::removeFactor(self::servedCaller(), $removed->id);

        self::assertTrue($result->wasMade(), (string) $result->reason?->value);
        self::assertSame(self::expected([$other], 'factor_removed', $person, $person), self::revocations($fake));
    }

    /**
     * An operator's reset records each session it ends, by the operator.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperatorsResetRecordsEachSessionItEnds(): void
    {
        $person   = $this->createPerson();
        $operator = $this->createPerson('operator@example.test');
        $sessions = [$this->inTenant($this->signIn($person)->record), $this->inTenant($this->signIn($person)->record)];

        $acting = $this->signIn($operator)->record;

        $acting->forceFill([$acting->getTenantIdName() => 'tenant-2'])->save();

        $this->actingOnSession($acting, self::GUARD);
        $this->confirmedFactor($person);

        $fake = AuditLog::fake();

        Mfa::resetIdentity($person, Actor::of($operator), 'Lost the phone the factor was on.');

        self::assertSame(self::expected($sessions, 'factor_reset', $person, $operator), self::revocations($fake));
    }

    /**
     * Record the session as acting in the tests' tenant.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function inTenant(EloquentSession&Model $session): EloquentSession&Model
    {
        $session->forceFill([$session->getTenantIdName() => self::TENANT])->save();

        return $session;
    }

    /**
     * The session, reason, subject, tenant, actor and principal of each
     * revocation the fake holds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore  $fake
     * @return list<list<mixed>>
     */
    private static function revocations(FakeAuditStore $fake): array
    {
        return array_map(static fn (AuditRecord $record): array => [
            $record->sessionId,
            $record->properties['reason'] ?? null,
            [$record->subjectType, $record->subjectId],
            [$record->tenantType, $record->tenantId],
            [$record->actorType, $record->actorId],
            [$record->principalType, $record->principalId],
        ], $fake->recorded(static fn (AuditRecord $record): bool => $record->event === 'session.revoked'));
    }

    /**
     * What each session's revocation holds: the person's, in the tests' tenant,
     * by the actor acting as itself, or by no one.
     *
     * @param  list<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>  $sessions
     * @param  string  $reason
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  ?\Tests\Fixtures\Models\Person  $actor
     * @return list<list<mixed>>
     */
    private static function expected(array $sessions, string $reason, Person $person, ?Person $actor): array
    {
        $by = $actor === null ? [null, null] : [Person::class, self::keyOf($actor)];

        return array_map(static fn (Model $session): array => [
            self::keyOf($session),
            $reason,
            [Person::class, self::keyOf($person)],
            [References::TENANT_TYPE, self::TENANT],
            $by,
            $by,
        ], $sessions);
    }
}
