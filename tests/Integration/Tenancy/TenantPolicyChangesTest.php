<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\TenantPolicyChanges;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\TestCase;

/**
 * Integration tests for a change of a tenant's authentication policy the
 * application reports itself (IAM-4.5), applied with the strict cut-off
 * `laravel-authentication`'s `tenantPolicyChanged()` asks for: inside the
 * transaction that publishes it, the tenant's sessions are judged at once and
 * once more when that transaction commits, so a session that entered the tenant
 * once the first pass had run is revoked then; a change rolled back runs no
 * second pass; with no transaction open the tenant is judged once; and the
 * service is the one the facade answers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantPolicyChanges::class)]
final class TenantPolicyChangesTest extends TestCase
{
    use MigratesMembers, SignsInPeople;

    /** @var string The tenant whose policy changes. */
    private const string TENANT = 'tenant-1';

    /** @var int How many times the tenant authentication policy has been asked. */
    private int $asked = 0;

    /**
     * Inside the transaction that publishes the change, the tenant's sessions
     * are judged at once, and once more when that transaction commits: a
     * session that entered the tenant once the first pass had run still stands
     * until then, and is revoked once the change commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideATransactionTheTenantIsJudgedNowAndOnceItCommits(): void
    {
        $this->bindPolicy(new TenantRequirement('7', connections: ['connection-1']));

        $early = $this->inTenant($this->signIn($this->createPerson())->record);
        $late  = $this->signIn($this->createPerson())->record;

        DB::connection(StorageConnection::name())->transaction(function () use ($early, $late): void {

            self::assertSame(1, Iam::tenantPolicies()->changed(new ClaimedTenant(self::TENANT)));
            self::assertNotNull($this->stored($early)->getRevokedAt());

            $this->inTenant($late);

            self::assertNull($this->stored($late)->getRevokedAt(), 'The second pass ran before the change committed.');
        });

        $stored = $this->stored($late);

        self::assertNotNull($stored->getRevokedAt(), 'The session that entered the tenant during the change still stands.');
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $stored->getRevokedReason());
    }

    /**
     * A change rolled back runs no second pass, the first pass's revocation
     * rolled back with it, however the unit of work ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackChangeRunsNoSecondPass(): void
    {
        $this->bindPolicy(new TenantRequirement('7', connections: ['connection-1']));

        $session = $this->inTenant($this->signIn($this->createPerson())->record);

        try {
            DB::connection(StorageConnection::name())->transaction(function (): void {

                Iam::tenantPolicies()->changed(new ClaimedTenant(self::TENANT));

                throw new \RuntimeException('The change failed.');
            });
        } catch (\RuntimeException) {
            // The application's change failed after the first pass.
        }

        $this->app?->terminate();

        self::assertSame(1, $this->asked, 'A second pass ran for a change rolled back.');
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * With no transaction open, the tenant is judged once, and a session that
     * meets the policy is kept at the version answered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoTransactionOpenTheTenantIsJudgedOnce(): void
    {
        $this->bindPolicy(new TenantRequirement('7'));

        $session = $this->inTenant($this->signIn($this->createPerson())->record);

        self::assertSame(0, Iam::tenantPolicies()->changed(new ClaimedTenant(self::TENANT)));
        self::assertSame(1, $this->asked);
        self::assertNull($this->stored($session)->getRevokedAt());
        self::assertSame('7', $this->stored($session)->getTenantPolicyVersion());
    }

    /**
     * Bind a tenancy in which every tenant resolves, and a tenant
     * authentication policy that answers the requirement, counting each time it
     * is asked.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement  $requirement
     * @return void
     */
    private function bindPolicy(TenantRequirement $requirement): void
    {
        $policy = \Mockery::mock(TenantAuthenticationPolicy::class);

        $policy->allows('requirementFor')->andReturnUsing(function () use ($requirement): TenantRequirement {

            $this->asked++;

            return $requirement;
        });

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAuthenticationPolicy::class, $policy);
    }

    /**
     * The session, made to act in the tenant.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function inTenant(EloquentSession&Model $session): EloquentSession&Model
    {
        $session->newQuery()->whereKey($session->getKey())->update([$session->getTenantIdName() => self::TENANT]);

        return $session;
    }

    /**
     * The session as it is stored now.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function stored(EloquentSession&Model $session): EloquentSession&Model
    {
        $stored = $session->newQuery()->find($session->getKey());

        self::assertInstanceOf(EloquentSession::class, $stored);
        self::assertInstanceOf(Model::class, $stored);

        return $stored;
    }
}
