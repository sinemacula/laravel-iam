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
 * Integration tests for a change of the application's MFA tenant requirement
 * reported as IAM-4.5 asks, against the strict cut-off
 * `laravel-authentication`'s `tenantPolicyChanged()` asks for: the application
 * changes its own data so the tenant requires a further factor and reports the
 * change inside the same transaction; a password sign-in in the tenant, which
 * read the requirement as it was before the change, writes its session on
 * another connection to the same database once the report's first pass has read
 * the tenant's sessions, so the first pass never judges it, and the session is
 * revoked once the change commits.
 *
 * Which of the change's moments the sign-in commits at, by database and
 * isolation level, is as `SignsInDuringTheFirstPass` describes.
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
     * Arrange a tenancy in which everyone may act in every tenant, and the
     * application's MFA tenant requirement, kept in its own table, under which
     * the tenant requires no further factor yet.
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
     * Roll back what is left open on the other connection, so neither the
     * requirements' table nor the migrations' rollback waits on it, and drop
     * the table.
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
     * A password session that entered the tenant on another connection once the
     * report's first pass had read the tenant's sessions, judged against the
     * requirement as it was before the change, is revoked once the change
     * commits.
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
