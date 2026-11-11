<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Tenancy\SubtreePolicyChanges;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Account;
use Tests\Fixtures\Authorization\AccountTenancy;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Integration tests for judging a subtree's sessions against the tenant policy
 * (IAM-7.5): every session in the tenant and the tenants below it, of whatever
 * type, is judged, every other left alone; with a flat tree only the tenant is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubtreePolicyChanges::class)]
#[WithConfig('authorization.tenant_tree', StoredTenantTree::class, defer: false)]
final class SubtreePolicyChangesTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The organisation whose subtree is judged. */
    private const string ORGANISATION = 'organisation-1';

    /** @var string The account below it. */
    private const string ACCOUNT = Account::PREFIX . '1';

    /** @var string An organisation apart. */
    private const string APART = 'organisation-2';

    /**
     * Arrange an account below an organisation, an organisation apart, and a
     * tenant requirement asking each of them for a second factor.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->app?->instance(TenantResolver::class, new AccountTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);

        StoredTenantTree::place(new Reference(Organisation::TYPE, self::ORGANISATION));
        StoredTenantTree::place(new Reference(Account::TYPE, self::ACCOUNT), new Reference(Organisation::TYPE, self::ORGANISATION));
        StoredTenantTree::place(new Reference(Organisation::TYPE, self::APART));
    }

    /**
     * A change judges every session in the tenant and in the tenant of another
     * type below it, and none apart.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testEverySessionInTheSubtreeIsJudged(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();
        $judged = [$this->signInIn($person, self::ORGANISATION), $this->signInIn($person, self::ACCOUNT)];
        $apart  = $this->signInIn($person, self::APART);

        $this->requireMultifactor();

        self::assertSame(2, DB::transaction(fn (): int => $this->changes()->changed(self::ORGANISATION)));

        foreach ($judged as $session) {
            self::assertNotNull($this->stored($session)->getRevokedAt(), (string) $session->getTenantId());
        }

        self::assertNull($this->stored($apart)->getRevokedAt());
    }

    /**
     * With `laravel-authorization`'s flat tree only the tenant's own sessions
     * are judged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithAFlatTreeOnlyTheTenantIsJudged(): void
    {
        $person       = $this->createPerson();
        $organisation = $this->signInIn($person, self::ORGANISATION);
        $account      = $this->signInIn($person, self::ACCOUNT);

        $this->requireMultifactor();

        $this->app?->instance(TenantTree::class, new FlatTenantTree);

        self::assertSame(1, DB::transaction(fn (): int => $this->changes()->changed(self::ORGANISATION)));
        self::assertNotNull($this->stored($organisation)->getRevokedAt());
        self::assertNull($this->stored($account)->getRevokedAt());
    }

    /**
     * Have every tenant require a second factor, which no password session
     * holds.
     *
     * @return void
     */
    private function requireMultifactor(): void
    {
        $requirement = ScriptedTenantRequirement::bind($this->app);

        foreach ([self::ORGANISATION, self::ACCOUNT, self::APART] as $tenantId) {
            $requirement->require($tenantId, Requirement::none()->withMultifactor(300));
        }
    }

    /**
     * Sign the person in with their password, acting in the tenant.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $tenantId
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function signInIn(Person $person, string $tenantId): EloquentSession&Model
    {
        $context = new SignInContext(self::client(), tenant: TenantSelection::of($tenantId));
        $result  = $this->sessions()->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], $context);

        self::assertTrue($result->isSignedIn(), (string) $result->reason?->value);

        return $result->session->record ?? self::fail('The sign-in established no session.');
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

    /**
     * The service under test.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\SubtreePolicyChanges
     */
    private function changes(): SubtreePolicyChanges
    {
        return $this->app?->make(SubtreePolicyChanges::class) ?? self::fail('The application has not booted.');
    }
}
