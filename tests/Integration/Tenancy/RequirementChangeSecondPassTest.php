<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\TenantPolicyChanges;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInDuringTheFirstPass;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\ReadsStoredRequirements;
use Tests\TestCase;

/**
 * Integration tests for a reported MFA requirement change's second pass.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantPolicyChanges::class)]
final class RequirementChangeSecondPassTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInDuringTheFirstPass, SignsInPeople;

    /**
     * Arrange an open tenancy and a stored MFA tenant requirement.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::requireIsolationLevels();

        ReadsStoredRequirements::createTable(self::CONNECTION);

        DB::table(ReadsStoredRequirements::TABLE)->insert(['tenant_id' => self::TENANT, 'multifactor' => false]);

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);
        $this->app?->instance(TenantRequirement::class, new ReadsStoredRequirements);
    }

    /**
     * Roll back the other connection and drop the requirements table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->rollBackElsewhere();

        if ($this->app !== null) {
            ReadsStoredRequirements::dropTable(self::CONNECTION);
        }

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

        Iam::transaction(static function (): void {

            DB::table(ReadsStoredRequirements::TABLE)->where('tenant_id', self::TENANT)->update(['multifactor' => true]);

            Iam::tenantPolicies()->changed(new ClaimedTenant(self::TENANT));
        });

        self::assertCount(1, $written, 'The sign-in did not run while the change did.');

        $session = DB::table('authentication_sessions')->where('id', $written[0])->first() ?? self::fail('The sign-in\'s session was not committed.');

        self::assertSame(self::TENANT, $session->tenant_id);
        self::assertNotNull($session->revoked_at, 'The session that entered the tenant during the change still stands.');
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $session->revoked_reason);
    }
}
