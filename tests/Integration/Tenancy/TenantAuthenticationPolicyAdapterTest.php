<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\TenantMfaRequirementMisconfiguredException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRequirements;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRule;
use SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;
use Tests\Concerns\CountsLockingReads;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Tenancy\ExemptsIdentities;
use Tests\Fixtures\Tenancy\LandlordTenant;
use Tests\Fixtures\Tenancy\ReadsLandlordRequirements;
use Tests\Fixtures\Tenancy\ScriptedEnforcement;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authentication`'s tenant authentication
 * policy, answered from SSO's enforcement, SSO's exemption gate and the
 * application's tenant MFA requirement (IAM-4.5): an enforced tenant requires
 * its satisfying connections, of a session and of a sign-in alike, judged by
 * the connection the context names, asked for only when the rule requires one; the gate is asked only for a session the rule would refuse, and
 * an exempt identity then needs no connection and its exemption is reported
 * once; the application's requirement is the further factor; the version
 * changes when the enforcement, the exemption or the requirement does, and
 * stays while none does; nothing is cached; the application's requirement is
 * read on the write connection; the adapter takes no lock of its own, under the
 * session's lock or outside a transaction, at either isolation level; and a
 * tenant that cannot be named, or a requirement that cannot be built, throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantAuthenticationPolicyAdapter::class)]
final class TenantAuthenticationPolicyAdapterTest extends TestCase
{
    use CountsLockingReads, MigratesMembers, RunsAtIsolationLevels, SignsInPeople, SignsInThroughLinks;

    /** @var string A connection of the tenant's no rule here names. */
    private const string OTHER_CONNECTION = 'connection-9';

    /** @var ?\Tests\Fixtures\Tenancy\ScriptedEnforcement SSO's enforcement, as each test scripts it. */
    private ?ScriptedEnforcement $enforcement = null;

    /** @var ?\Tests\Fixtures\Tenancy\ExemptsIdentities SSO's exemption contract, as each test scripts it. */
    private ?ExemptsIdentities $exemptions = null;

    /**
     * Script SSO's enforcement and exemption contract, and record the
     * exemptions SSO reports.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->enforcement = new ScriptedEnforcement;
        $this->exemptions  = new ExemptsIdentities;

        $this->app?->instance(Enforcement::class, $this->enforcement);
        $this->app?->instance(EnforcementExemption::class, $this->exemptions);

        Event::fake([ExemptionUsed::class]);
    }

    /**
     * The adapter is the tenant authentication policy bound.
     *
     * @return void
     */
    public function testTheAdapterIsThePolicyBound(): void
    {
        self::assertInstanceOf(TenantAuthenticationPolicyAdapter::class, $this->resolved(TenantAuthenticationPolicy::class));
    }

    /**
     * With SSO's enforcement off and no tenant MFA requirement, nothing is
     * required, at a version, and nothing is read.
     *
     * @return void
     */
    public function testWithNothingOnNothingIsRequiredAndNothingRead(): void
    {
        $this->app?->instance(Enforcement::class, $this->app->make(DatabaseEnforcement::class));

        $person  = $this->createPerson();
        $session = $this->signInThrough($person);
        $queries = $this->countQueries(fn (): TenantRequirement => $this->ask($person, $session));

        $requirement = $this->ask($person, $session);

        self::assertSame(0, $queries);
        self::assertNull($requirement->connections);
        self::assertTrue($requirement->factor->isEmpty());
        self::assertNotNull($requirement->version);
    }

    /**
     * An enforced tenant requires its satisfying connections of a session
     * established through one of them, and the gate is not asked.
     *
     * @return void
     */
    public function testAnEnforcedTenantRequiresItsConnections(): void
    {
        $this->enforcement()->requireThrough([self::SSO_CONNECTION, 'connection-2']);

        $person      = $this->createPerson();
        $requirement = $this->ask($person, $this->signInThrough($person));

        self::assertSame([self::SSO_CONNECTION, 'connection-2'], $requirement->connections);
        self::assertTrue($requirement->admitsConnection(self::SSO_CONNECTION));
        self::assertSame([], $this->exemptions()->asked());
        self::assertSame([['tenant' => self::SSO_TENANT, 'application' => self::GUARD]], $this->enforcement()->asked());
        Event::assertNotDispatched(ExemptionUsed::class);
    }

    /**
     * Rows of how a session the rule would refuse was established.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideRefusedSessions(): iterable
    {
        yield 'through another connection' => [true];

        yield 'with a password' => [false];
    }

    /**
     * A session the rule would refuse is judged by the gate: an identity that
     * is not exempt is required to come through the rule's connections, and
     * nothing is reported.
     *
     * @param  bool  $external
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusedSessions')]
    public function testASessionTheRuleWouldRefuseIsJudgedByTheGate(bool $external): void
    {
        $this->enforcement()->requireThrough([self::SSO_CONNECTION]);

        $person      = $this->createPerson();
        $session     = $external ? $this->signInThrough($person, self::OTHER_CONNECTION) : $this->signIn($person)->record;
        $requirement = $this->ask($person, $session);

        self::assertSame([self::SSO_CONNECTION], $requirement->connections);
        self::assertCount(1, $this->exemptions()->asked());
        self::assertTrue($this->exemptions()->asked()[0]->is(self::referenceOf($person)));
        Event::assertNotDispatched(ExemptionUsed::class);
    }

    /**
     * An exempt identity's session the rule would refuse needs no connection,
     * and its exemption is reported once, naming the session and carrying no
     * client, since `laravel-authentication` hands the policy none.
     *
     * @return void
     */
    public function testAnExemptIdentitysSessionNeedsNoConnection(): void
    {
        $this->enforcement()->requireThrough([self::SSO_CONNECTION], 'enforcement-3');

        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;

        $this->exemptions()->exempt(self::referenceOf($person));

        $requirement = $this->ask($person, $session);

        self::assertNull($requirement->connections);
        Event::assertDispatchedTimes(ExemptionUsed::class, 1);
        Event::assertDispatched(ExemptionUsed::class, static fn (ExemptionUsed $event): bool => $event->context->sessionId === self::keyOf($session)
            && $event->context->identityId                                                                                 === self::keyOf($person)
            && $event->context->tenantId                                                                                   === self::SSO_TENANT
            && $event->context->application                                                                                === self::GUARD
            && $event->context->ip                                                                                         === null
            && $event->context->userAgent                                                                                  === null
            && $event->enforcementVersion                                                                                  === 'enforcement-3');
    }

    /**
     * An exempt identity's session through a satisfying connection is never
     * judged by the gate, so no exemption is reported for a session that never
     * needed one.
     *
     * @return void
     */
    public function testAnExemptIdentitysCompliantSessionReportsNoExemption(): void
    {
        $this->enforcement()->requireThrough([self::SSO_CONNECTION]);

        $person = $this->createPerson();

        $this->exemptions()->exempt(self::referenceOf($person));

        self::assertSame([self::SSO_CONNECTION], $this->ask($person, $this->signInThrough($person))->connections);
        self::assertSame([], $this->exemptions()->asked());
        Event::assertNotDispatched(ExemptionUsed::class);
    }

    /**
     * A sign-in, whose session is not written yet, is established through the
     * connection the context names, as `laravel-authentication` names it from
     * the sign-in's evidence, so the gate is not asked for one through a
     * satisfying connection.
     *
     * @return void
     */
    public function testASignInThroughASatisfyingConnectionNeedsNoGate(): void
    {
        $this->enforcement()->requireThrough([self::SSO_CONNECTION]);

        $requirement = $this->askThrough($this->createPerson(), null, self::SSO_CONNECTION);

        self::assertSame([self::SSO_CONNECTION], $requirement->connections);
        self::assertSame([], $this->exemptions()->asked());
    }

    /**
     * A sign-in through no connection (a password sign-in), or through one the
     * rule does not list, is judged by the gate, and an exemption it grants
     * names no session.
     *
     * @return void
     */
    public function testASignInThroughNoSatisfyingConnectionIsJudgedByTheGate(): void
    {
        $this->enforcement()->requireThrough([self::SSO_CONNECTION]);

        [$ada, $grace] = [$this->createPerson(), $this->createPerson()];

        $this->exemptions()->exempt(self::referenceOf($ada));

        self::assertNull($this->askThrough($ada, null, null)->connections);
        self::assertSame([self::SSO_CONNECTION], $this->askThrough($grace, null, self::OTHER_CONNECTION)->connections);
        self::assertCount(2, $this->exemptions()->asked());
        Event::assertDispatched(ExemptionUsed::class, static fn (ExemptionUsed $event): bool => $event->context->sessionId === null);
    }

    /**
     * The connection is asked for only once the rule requires one: a tenant
     * whose rule requires none never asks, so it costs no read of the session's
     * provenance.
     *
     * @return void
     */
    public function testTheConnectionIsAskedForOnlyWhenTheRuleRequiresOne(): void
    {
        $asked      = new \ArrayObject;
        $person     = $this->createPerson();
        $connection = static function () use ($asked): string {
            $asked->append(true);

            return self::SSO_CONNECTION;
        };
        $ask = function () use ($person, $connection): TenantRequirement {
            $policy = $this->resolved(TenantAuthenticationPolicy::class);

            self::assertInstanceOf(TenantAuthenticationPolicy::class, $policy);

            return $policy->requirementFor(new TenantPolicyContext(self::GUARD, $person, $person, new ClaimedTenant(self::SSO_TENANT), null, $connection));
        };

        self::assertNull($ask()->connections);
        self::assertCount(0, $asked);

        $this->enforcement()->requireThrough([self::SSO_CONNECTION]);

        self::assertSame([self::SSO_CONNECTION], $ask()->connections);
        self::assertCount(1, $asked);
    }

    /**
     * A rule whose every satisfying connection has gone is satisfied by none,
     * so the gate judges every session.
     *
     * @return void
     */
    public function testARuleWithNoConnectionLeftIsSatisfiedByNone(): void
    {
        $this->enforcement()->requireThrough([]);

        $person      = $this->createPerson();
        $requirement = $this->ask($person, $this->signInThrough($person));

        self::assertSame([], $requirement->connections);
        self::assertFalse($requirement->admitsConnection(self::SSO_CONNECTION));
        self::assertCount(1, $this->exemptions()->asked());
    }

    /**
     * The application's tenant MFA requirement for exactly the tenant asked is
     * the further factor, whatever SSO's enforcement says.
     *
     * @return void
     */
    public function testTheApplicationsRequirementIsTheFurtherFactor(): void
    {
        $fake = FakeTenantMfaRequirement::fake($this->app)->require(self::SSO_TENANT, self::multifactor());

        $person = $this->createPerson();

        self::assertEquals(self::multifactor(), $this->ask($person, $this->signIn($person)->record)->factor);
        self::assertTrue($this->ask($person, $this->signIn($person)->record, new ClaimedTenant('tenant-2'))->factor->isEmpty());
        self::assertSame([['tenant' => self::SSO_TENANT, 'application' => self::GUARD], ['tenant' => 'tenant-2', 'application' => self::GUARD]], $fake->asked());
    }

    /**
     * The version stays the same while nothing changes, and changes when the
     * enforcement's rule, its connections, the exemption or the application's
     * requirement does; nothing is cached, so each change is answered at once.
     *
     * @return void
     */
    public function testTheVersionChangesWhenAnyInputChanges(): void
    {
        $fake    = FakeTenantMfaRequirement::fake($this->app);
        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;
        $seen    = [];

        $ask = function () use ($session, $person, &$seen): TenantRequirement {
            $requirement = $this->ask($person, $session);

            self::assertSame($requirement->version, $this->ask($person, $session)->version, 'The version changed with nothing changed.');

            $seen[] = $requirement->version;

            return $requirement;
        };

        $ask();
        $this->enforcement()->requireThrough([self::SSO_CONNECTION], 'enforcement-1');
        self::assertSame([self::SSO_CONNECTION], $ask()->connections);
        $this->enforcement()->requireThrough([self::SSO_CONNECTION], 'enforcement-2');
        $ask();
        $this->enforcement()->requireThrough([self::SSO_CONNECTION, 'connection-2'], 'enforcement-2');
        $ask();
        $this->exemptions()->exempt(self::referenceOf($person));
        self::assertNull($ask()->connections);
        $fake->require(self::SSO_TENANT, self::multifactor());
        self::assertFalse($ask()->factor->isEmpty());
        $fake->require(self::SSO_TENANT, new Requirement(multifactor: new RequirementPart(60)));
        $ask();
        $this->enforcement()->requireNothing();
        $ask();

        self::assertCount(8, array_unique(array_filter($seen, static fn (?string $version): bool => $version !== null)));
    }

    /**
     * An application's requirement that requires something but cannot be
     * versioned makes the answer's version none, so it is never taken as
     * already checked.
     *
     * @return void
     */
    public function testAnUnversionedRequirementIsAnsweredAtNoVersion(): void
    {
        $requirement = \Mockery::mock(TenantMfaRequirement::class);

        $requirement->allows('requirementFor')->andReturn(new TenantMfaRule(self::multifactor()));

        $this->app?->instance(TenantMfaRequirement::class, $requirement);

        $person = $this->createPerson();

        self::assertNull($this->ask($person, $this->signIn($person)->record)->version);
    }

    /**
     * The application's requirement is asked with its model reads pinned to the
     * write connection, wherever the tenant's data lives: a requirement the
     * primary holds and its replica has not yet seen is answered, not refused.
     *
     * @return void
     */
    public function testTheApplicationsRequirementIsReadOnTheWriteConnection(): void
    {
        $this->app?->make('config')->set('database.connections.' . LandlordTenant::CONNECTION, [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
            'read'     => ['database' => ':memory:'],
            'write'    => ['database' => ':memory:'],
        ]);

        $connection = DB::connection(LandlordTenant::CONNECTION);

        foreach ([$connection->getPdo(), $connection->getReadPdo()] as $pdo) {
            $pdo->exec('create table ' . LandlordTenant::TABLE . ' (id varchar(255) not null primary key)');
        }

        $connection->getPdo()->exec('insert into ' . LandlordTenant::TABLE . ' (id) values (\'tenant-1\')');

        $requirement = new ReadsLandlordRequirements;

        $this->app?->instance(TenantMfaRequirement::class, $requirement);

        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;

        self::assertNull(LandlordTenant::query()->find(self::SSO_TENANT), 'The replica must lag the primary for this test to prove anything.');
        self::assertFalse($this->ask($person, $session)->factor->isEmpty());
        self::assertNull(LandlordTenant::query()->find(self::SSO_TENANT), 'The connection must read from its replica again once the requirement is answered.');
    }

    /**
     * Asked while the transaction holds the session's row locked, as a refresh,
     * a switch and an external re-authentication ask it, the adapter judges by
     * the connection the context names and takes no lock of its own, at either
     * isolation level; SSO's own enforcement, with a rule stored, is asked in
     * `EnforcementThroughTenantPolicyTest`, and a session committed after the
     * transaction's snapshot, judged through `laravel-authentication`'s own
     * lookup, in `CompliantSessionUnderAnOlderSnapshotTest`.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testItTakesNoLockUnderTheSessionsLock(string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->enforcement()->requireThrough([self::SSO_CONNECTION]);

        $person  = $this->createPerson();
        $session = $this->signInThrough($person);

        [$requirement, $locks] = $this->askedUnderTheSessionsLock($session, fn (): TenantRequirement => $this->askThrough($person, $session, self::SSO_CONNECTION));

        self::assertSame([self::SSO_CONNECTION], $requirement->connections);
        self::assertSame([], $this->exemptions()->asked());
        self::assertSame([], $locks, 'The adapter took a lock of its own.');
    }

    /**
     * Asked outside any transaction, where nothing acts on the answer
     * atomically, the adapter judges by the session's recorded connection and
     * takes no lock, at either isolation level.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testItTakesNoLockOutsideATransaction(string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->enforcement()->requireThrough([self::SSO_CONNECTION]);

        $person  = $this->createPerson();
        $session = $this->signInThrough($person);

        [$requirement, $locks] = self::askedOutsideATransaction(fn (): TenantRequirement => $this->ask($person, $session));

        self::assertSame([self::SSO_CONNECTION], $requirement->connections);
        self::assertSame([], $this->exemptions()->asked());
        self::assertSame([], $locks, 'The adapter took a lock outside a transaction.');
    }

    /**
     * A tenant whose identifier can name it to no member throws, so the session
     * is refused rather than judged against no policy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantThatCannotBeNamedThrows(): void
    {
        $tenant = \Mockery::mock(Tenant::class);

        $tenant->allows('getTenantIdentifier')->andReturn(null);

        $person = $this->createPerson();

        try {
            $this->ask($person, $this->signIn($person)->record, $tenant);

            self::fail('The policy answered.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::TENANT, $exception->kind);
        }

        self::assertSame([], $this->enforcement()->asked());
    }

    /**
     * A tenant MFA requirement named that is no requirement throws, rather than
     * answer that the tenant requires nothing.
     *
     * @return void
     */
    public function testARequirementThatCannotBeBuiltThrows(): void
    {
        $this->app?->make('config')->set(TenantMfaRequirements::KEY, \stdClass::class);

        $this->expectException(TenantMfaRequirementMisconfiguredException::class);

        $person = $this->createPerson();

        $this->ask($person, $this->signIn($person)->record);
    }

    /**
     * What the policy bound answers for the person's session in the tenant, on
     * the guard, established through the connection its recorded provenance
     * names, read only once the policy asks.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
     */
    private function ask(Person $person, Session $session, ?Tenant $tenant = null): TenantRequirement
    {
        $policy = $this->app?->make(TenantAuthenticationPolicy::class) ?? self::fail('The application has not booted.');

        $context = self::tenantPolicyContext($person, $person, $tenant ?? new ClaimedTenant(self::SSO_TENANT), $session, fn (): ?string => $this->recordedConnectionOf($session));

        return $policy->requirementFor($context);
    }

    /**
     * What the policy bound answers for the person's session in the tenant, or
     * their sign-in whose session is not written yet (no session), on the
     * guard, established through the connection given, or through none.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?string  $connectionId
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
     */
    private function askThrough(Person $person, ?Session $session, ?string $connectionId): TenantRequirement
    {
        $policy = $this->app?->make(TenantAuthenticationPolicy::class) ?? self::fail('The application has not booted.');

        return $policy->requirementFor(self::tenantPolicyContext($person, $person, new ClaimedTenant(self::SSO_TENANT), $session, static fn (): ?string => $connectionId));
    }

    /**
     * What the container resolves the abstract to.
     *
     * @param  string  $abstract
     * @return mixed
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }

    /**
     * How many queries the call ran.
     *
     * @param  \Closure(): mixed  $call
     * @return int
     */
    private function countQueries(\Closure $call): int
    {
        $count = 0;

        DB::listen(static function () use (&$count): void {
            $count++;
        });

        $call();

        return $count;
    }

    /**
     * SSO's enforcement, as the test scripts it.
     *
     * @return \Tests\Fixtures\Tenancy\ScriptedEnforcement
     */
    private function enforcement(): ScriptedEnforcement
    {
        return $this->enforcement ?? self::fail('The enforcement is not scripted.');
    }

    /**
     * SSO's exemption contract, as the test scripts it.
     *
     * @return \Tests\Fixtures\Tenancy\ExemptsIdentities
     */
    private function exemptions(): ExemptsIdentities
    {
        return $this->exemptions ?? self::fail('The exemptions are not scripted.');
    }

    /**
     * Multifactor authentication within five minutes.
     *
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    private static function multifactor(): Requirement
    {
        return new Requirement(multifactor: new RequirementPart(300));
    }
}
