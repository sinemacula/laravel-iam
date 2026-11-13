<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement as MfaTenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;
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
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\TestCase;

/**
 * Integration tests for the tenant authentication policy adapter.
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
     * Script SSO's enforcement and exemption, and record reported exemptions.
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
     * With nothing on nothing is required or read.
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
     * An enforced tenant requires its connections.
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
     * A session the rule would refuse is judged by the gate.
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
     * An exempt identity's session needs no connection.
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
     * A session judged again is exempt without reporting the exemption.
     *
     * @return void
     */
    public function testASessionJudgedAgainIsExemptWithoutReportingIt(): void
    {
        $this->enforcement()->requireThrough([self::SSO_CONNECTION]);

        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;
        $policy  = $this->app?->make(TenantAuthenticationPolicy::class) ?? self::fail('The application has not booted.');
        $context = new TenantPolicyContext(self::GUARD, $person, $person, new ClaimedTenant(self::SSO_TENANT), $session, static fn (): ?string => null, rejudging: true);

        $this->exemptions()->exempt(self::referenceOf($person));

        self::assertNull($policy->requirementFor($context)->connections);
        self::assertCount(1, $this->exemptions()->asked());
        Event::assertNotDispatched(ExemptionUsed::class);
    }

    /**
     * An exempt identity's compliant session reports no exemption.
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
     * A sign-in through a satisfying connection needs no gate.
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
     * A sign-in through no satisfying connection is judged by the gate.
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
     * The connection is asked for only when the rule requires one.
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
     * A rule with no connection left is satisfied by none.
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
     * The application's requirement is the further factor.
     *
     * @return void
     */
    public function testTheApplicationsRequirementIsTheFurtherFactor(): void
    {
        $fake = $this->scriptedRequirement()->require(self::SSO_TENANT, MfaRequirement::none()->withMultifactor(300));

        $person = $this->createPerson();

        self::assertEquals(self::multifactor(), $this->ask($person, $this->signIn($person)->record)->factor);
        self::assertTrue($this->ask($person, $this->signIn($person)->record, new ClaimedTenant('tenant-2'))->factor->isEmpty());
        self::assertSame([['tenant' => self::SSO_TENANT, 'application' => self::GUARD], ['tenant' => 'tenant-2', 'application' => self::GUARD]], $fake->asked());
    }

    /**
     * The version changes when any input changes.
     *
     * @return void
     */
    public function testTheVersionChangesWhenAnyInputChanges(): void
    {
        $fake    = $this->scriptedRequirement();
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
        $fake->require(self::SSO_TENANT, MfaRequirement::none()->withMultifactor(300));
        self::assertFalse($ask()->factor->isEmpty());
        $fake->require(self::SSO_TENANT, MfaRequirement::none()->withMultifactor(60));
        $ask();
        $this->enforcement()->requireNothing();
        $ask();

        self::assertCount(8, array_unique($seen));
    }

    /**
     * The application's requirement is read on the write connection.
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

        $this->app?->instance(MfaTenantRequirement::class, $requirement);

        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;

        self::assertNull(LandlordTenant::query()->find(self::SSO_TENANT), 'The replica must lag the primary for this test to prove anything.');
        self::assertFalse($this->ask($person, $session)->factor->isEmpty());
        self::assertNull(LandlordTenant::query()->find(self::SSO_TENANT), 'The connection must read from its replica again once the requirement is answered.');
    }

    /**
     * It takes no lock under the session's lock.
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
     * It takes no lock outside a transaction.
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
     * A tenant that cannot be named throws.
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
     * An identity with no MFA factors is refused once a requirement is bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityMfaHoldsNoFactorsForIsRefusedOnceARequirementIsBound(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $policy   = $this->app?->make(TenantAuthenticationPolicy::class) ?? self::fail('The application has not booted.');
        $context  = new TenantPolicyContext(self::GUARD, $identity, $this->createPerson(), new ClaimedTenant(self::SSO_TENANT), null, static fn (): ?string => null);

        self::assertTrue($policy->requirementFor($context)->factor->isEmpty());

        $this->scriptedRequirement()->require(self::SSO_TENANT, MfaRequirement::none()->withMultifactor());

        $this->expectException(UnresolvedReferenceException::class);

        $policy->requirementFor($context);
    }

    /**
     * The policy's answer for the session, through its recorded connection.
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
     * The policy's answer for the session or sign-in, through a connection.
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
     * MFA's tenant requirement, scripted and bound for the test.
     *
     * @return \Tests\Fixtures\Tenancy\ScriptedTenantRequirement
     */
    private function scriptedRequirement(): ScriptedTenantRequirement
    {
        return ScriptedTenantRequirement::bind($this->app);
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
