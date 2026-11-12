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
 * Integration tests for the enforcement change's second pass over sessions.
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
     * Arrange SSO enforcement, an open tenancy and an enforceable connection.
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
     * A session that entered during the change is revoked once it commits.
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
