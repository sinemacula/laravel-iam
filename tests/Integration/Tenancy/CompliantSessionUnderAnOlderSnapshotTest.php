<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenantPolicyVersion;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Sso\Handoff;
use Tests\Fixtures\Tenancy\ExemptsIdentities;
use Tests\TestCase;

/**
 * Integration tests for judging a session committed after the snapshot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantAuthenticationPolicyAdapter::class)]
final class CompliantSessionUnderAnOlderSnapshotTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The second connection the sign-in is made on. */
    private const string ELSEWHERE = 'elsewhere';

    /** @var ?\Tests\Fixtures\Tenancy\ExemptsIdentities The application's break-glass rule. */
    private ?ExemptsIdentities $exemptions = null;

    /**
     * Arrange SSO enforcement, an open tenancy and an exemption rule.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::requireIsolationLevels();

        $this->arrangeSso();

        Config::set('sso.features.enforcement', true);

        $this->exemptions = new ExemptsIdentities;

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);
        $this->app?->instance(EnforcementExemption::class, $this->exemptions);

        Event::fake([ExemptionUsed::class]);
    }

    /**
     * Roll back what is left open, so the migrations' rollback never waits.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connections = $this->app?->make('db')->getConnections() ?? [];

        foreach ([self::ELSEWHERE, self::CONNECTION] as $name) {

            $connection = $connections[$name] ?? null;

            while ($connection !== null && $connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        parent::tearDown();
    }

    /**
     * A compliant session committed after the snapshot skips the gate.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testACompliantSessionCommittedAfterTheSnapshotIsJudgedWithoutTheGate(string $level): void
    {
        $person = $this->createPerson();

        $this->linkThroughFlow($person);
        $this->enforce();
        $this->exemptions()->exempt(self::referenceOf($person));

        $handoff = $this->handoff();
        $storage = DB::connection(self::CONNECTION);

        self::useIsolationLevel($level);

        $storage->beginTransaction();

        // Fix the snapshot on MySQL at REPEATABLE READ, as SSO's reads do.
        $storage->table('authentication_provenance')->count();

        $session = $this->redeemElsewhere($handoff);

        $this->sessions()->tenantPolicyChanged(new ClaimedTenant(self::TENANT));

        $storage->commit();

        $stored = $session->newQuery()->find($session->getKey());

        self::assertInstanceOf(EloquentSession::class, $stored);

        $app     = $this->app ?? self::fail('The application has not booted.');
        $policy  = $app->make(Enforcement::class)->policy(self::TENANT, self::GUARD);
        $context = self::tenantPolicyContext($person, $person, new ClaimedTenant(self::TENANT), $stored, fn (): ?string => $this->recordedConnectionOf($stored));
        $answer  = $app->make(TenantAuthenticationPolicy::class)->requirementFor($context);

        self::assertSame([], $this->exemptions()->asked(), 'The gate was asked for a session through a satisfying connection.');
        Event::assertNotDispatched(ExemptionUsed::class);
        self::assertNull($stored->getRevokedAt());
        self::assertSame(TenantPolicyVersion::of($policy, null, new Requirement), $answer->version);
        self::assertSame($answer->version, $stored->getTenantPolicyVersion());
    }

    /**
     * Require sessions in the tenant to come through the tests' connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function enforce(): void
    {
        $handoff = $this->handoff();
        $signIn  = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $signIn);
        self::assertTrue($signIn->isSignedIn(), (string) $signIn->reason?->value);

        $service = $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');
        $result  = $service->update(self::TENANT, true, [$this->connectionId], self::ssoClient());

        self::assertTrue($result->isChanged(), sprintf('The enforcement did not change: [%s].', $result->reason->value ?? $result->status->value));
    }

    /**
     * Redeem the handoff on another connection and return the session.
     *
     * @param  \Tests\Fixtures\Sso\Handoff  $handoff
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function redeemElsewhere(Handoff $handoff): EloquentSession&Model
    {
        Config::set('database.connections.' . self::ELSEWHERE, Config::get('database.connections.' . self::CONNECTION));

        $default   = DB::getDefaultConnection();
        $elsewhere = DB::connection(self::ELSEWHERE);

        // Never wait long on a lock the judging transaction holds.
        $elsewhere->statement($elsewhere->getDriverName() === 'pgsql' ? 'set lock_timeout = \'5s\'' : 'set session innodb_lock_wait_timeout = 5');

        DB::setDefaultConnection(self::ELSEWHERE);

        try {
            $context = new SignInContext(self::client(), tenant: TenantSelection::of(self::TENANT));
            $answer  = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, $context);

            self::assertInstanceOf(SignInResult::class, $answer);
            self::assertTrue($answer->isSignedIn(), (string) $answer->reason?->value);

            return $answer->session->record ?? self::fail('The sign-in established no session.');
        } finally {
            DB::setDefaultConnection($default);
        }
    }

    /**
     * The application's break-glass rule.
     *
     * @return \Tests\Fixtures\Tenancy\ExemptsIdentities
     */
    private function exemptions(): ExemptsIdentities
    {
        return $this->exemptions ?? self::fail('The exemptions are not arranged.');
    }
}
