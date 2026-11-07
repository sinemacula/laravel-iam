<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInDuringTheFirstPass;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\TestCase;

/**
 * Integration tests for the second pass an enforcement change makes over the
 * enforcing tenant's sessions once SSO's transaction commits (IAM-4.4), against
 * the strict cut-off `laravel-authentication`'s `tenantPolicyChanged()` asks
 * for: a password sign-in in the tenant, which takes no lock of SSO's rule and
 * judged the tenant's policy before the rule was turned on, writes its session
 * on another connection to the same database once the change's first pass has
 * read the tenant's sessions, and the session is revoked once the change
 * commits.
 *
 * On PostgreSQL at either isolation level and on MySQL at READ COMMITTED the
 * sign-in commits after the change's first pass and before the change commits,
 * the first pass's locks holding no row it writes. On MySQL at REPEATABLE READ
 * the first pass's locking read holds the gap the session's row would go in, so
 * the sign-in's write waits for the change to commit and then goes ahead with
 * the verdict it made: the sign-in commits once the change has, before the
 * second pass runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevocationAdapter::class)]
final class EnforcementSecondPassTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInDuringTheFirstPass, SignsInPeople;

    /**
     * Arrange SSO with its enforcement on and no rule yet, a tenancy in which
     * everyone may act in every tenant, and the tests' connection marked as
     * having completed a sign-in, so SSO may enforce it.
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

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);

        DB::table('sso_connections')->where('id', $this->connectionId)->update(['has_completed_sign_in' => true]);
    }

    /**
     * Roll back what is left open on the other connection, so the migrations'
     * rollback never waits on it.
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
     * A password session that entered the tenant on another connection once the
     * change's first pass had read the tenant's sessions, and committed before
     * the second pass, recorded at the policy as it was before the rule, is
     * revoked once the change commits.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASessionThatEnteredTheTenantDuringTheChangeIsRevokedOnceItCommits(string $level): void
    {
        self::useIsolationLevel($level);

        $person = $this->createPerson();
        /** @var \ArrayObject<int, string> $written */
        $written = new \ArrayObject;

        $this->onceTheFirstPassHasRead($level, function () use ($person, $written): void {

            $written->append($this->signInElsewhere($person->email));
        });

        $service = $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');
        $result  = $service->update(self::TENANT, true, [$this->connectionId], self::ssoClient());

        self::assertTrue($result->isChanged(), sprintf('The enforcement did not change: [%s].', $result->reason->value ?? $result->status->value));
        self::assertCount(1, $written, 'The sign-in did not run while the change did.');

        $session = DB::table('authentication_sessions')->where('id', $written[0])->first() ?? self::fail('The sign-in\'s session was not committed.');

        self::assertSame(self::TENANT, $session->tenant_id);
        self::assertNotNull($session->revoked_at, 'The session that entered the tenant during the change still stands.');
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $session->revoked_reason);
    }
}
