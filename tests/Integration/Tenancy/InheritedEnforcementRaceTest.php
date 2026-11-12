<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Iam\Tenancy\EnforcementInheritanceAdapter;
use SineMacula\Laravel\Iam\Tenancy\SubtreePolicyChanges;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInDuringTheFirstPass;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Integration tests for a rule change racing an inheriting tenant's sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevocationAdapter::class)]
#[CoversClass(SubtreePolicyChanges::class)]
#[CoversClass(EnforcementInheritanceAdapter::class)]
#[WithConfig('authorization.tenant_tree', StoredTenantTree::class, defer: false)]
final class InheritedEnforcementRaceTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInDuringTheFirstPass, SignsInPeople;

    /** @var string The tests' tenant's parent, whose rule the tests' tenant inherits. */
    private const string PARENT = 'tenant-1-parent';

    /** @var ?string The parent's connection, which its rule names. */
    private ?string $parentConnection = null;

    /**
     * Arrange SSO enforcement, the tree, an open tenancy and the parent.
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

        StoredTenantTree::place(self::PARENT);
        StoredTenantTree::place(self::TENANT, self::PARENT);

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);

        $this->parentConnection = $this->makeConnection(self::PARENT);

        DB::table('sso_connections')->where('id', $this->parentConnection)->update(['has_completed_sign_in' => true]);
    }

    /**
     * Roll back what is left open, so the migrations' rollback never waits.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->rollBackElsewhere();

        parent::tearDown();
    }

    /**
     * A session that entered an inheriting tenant during the change is revoked.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASessionThatEnteredAnInheritingTenantDuringTheChangeIsRevoked(string $level): void
    {
        self::useIsolationLevel($level);

        $person = $this->createPerson();
        /** @var \ArrayObject<int, string> $written */
        $written = new \ArrayObject;

        $this->onceTheFirstPassHasRead($level, function () use ($person, $written): void {

            $written->append($this->signInElsewhere($person->email));
        });

        $service = $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');
        $result  = $service->update(self::PARENT, true, [(string) $this->parentConnection], self::ssoClient());

        self::assertTrue($result->isChanged(), sprintf('The enforcement did not change: [%s].', $result->reason->value ?? $result->status->value));
        self::assertCount(1, $written, 'The sign-in did not run while the change did.');

        $session = DB::table('authentication_sessions')->where('id', $written[0])->first() ?? self::fail('The sign-in\'s session was not committed.');

        self::assertSame(self::TENANT, $session->tenant_id);
        self::assertNotNull($session->revoked_at, 'The session that entered the inheriting tenant during the change still stands.');
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $session->revoked_reason);
    }
}
