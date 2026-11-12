<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TreeChanges;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Link;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\Fixtures\Authorization\Account;
use Tests\Fixtures\Authorization\AccountTenancy;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Integration tests for a tree move widening grants beyond a linked tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TreeChanges::class)]
#[WithConfig('authorization.tenant_tree', StoredTenantTree::class, defer: false)]
final class TreeMoveWideningTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople, SignsInThroughLinks {
        SignsInThroughLinks::keyOf insteadof RunsSsoFlows;
        SignsInThroughLinks::referenceOf insteadof RunsSsoFlows;
        SignsInThroughLinks::signInMethods insteadof RunsSsoFlows;
    }

    /** @var string The tenant of the person's link by a verified domain. */
    private const string LINKED = 'linked';

    /** @var string The tenant below the linked one that the person is granted in, and that moves. */
    private const string GRANTED = 'granted';

    /** @var string The granted tenant's child, which moves with it. */
    private const string GRANTED_CHILD = 'granted-child';

    /** @var string The role granted. */
    private const string ROLE = 'editor';

    /** @var ?\Tests\Fixtures\Models\Person The person granted in the granted tenant. */
    private ?Person $person = null;

    /** @var string The person's link by a verified domain, in the linked tenant's connection. */
    private string $linkId = '';

    /** @var string The linked tenant's connection. */
    private string $linkedConnectionId = '';

    /**
     * Arrange SSO, the tree, the role, the grantee and their domain link.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        StoredTenantTree::place(self::organisation(self::LINKED));
        StoredTenantTree::place(self::organisation(self::GRANTED), self::organisation(self::LINKED));
        StoredTenantTree::place(self::organisation(self::GRANTED_CHILD), self::organisation(self::GRANTED));

        $this->app?->instance(TenantResolver::class, new OrganisationTenancy);

        Role::query()->create(['name' => self::ROLE]);

        $person       = $this->createPerson();
        $this->person = $person;

        $this->grant($person, self::GRANTED);

        $this->linkedConnectionId = $this->makeConnection(self::LINKED);
        $tenantConnection         = $this->connectionId;
        $this->connectionId       = $this->linkedConnectionId;
        $this->linkId             = (string) $this->linkThroughFlow($person)->linkId;
        $this->connectionId       = $tenantConnection;

        Link::query()->whereKey($this->linkId)->update(['provenance' => LinkOrigin::VERIFIED_DOMAIN->value]);
    }

    /**
     * A move from under the linked tenant suspends the link in its transaction.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMoveOutFromUnderTheLinkedTenantSuspendsTheLinkInTheMovesTransaction(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->signInThrough($this->person(), $this->linkedConnectionId, $this->linkId);
        $inside  = Iam::transaction(function () use ($session): array {

            StoredTenantTree::place(self::organisation(self::GRANTED));

            Iam::treeChanges()->changed(self::GRANTED);

            return [$this->link()->state, $this->stored($session)->getRevokedAt()];
        });

        self::assertSame(LinkState::SUSPENDED, $inside[0]);
        self::assertNotNull($inside[1]);
        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
        self::assertNotNull($this->stored($session)->getRevokedAt());
    }

    /**
     * A move that rolls back suspends nothing.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMoveThatRollsBackSuspendsNothing(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session  = $this->signInThrough($this->person(), $this->linkedConnectionId, $this->linkId);
        $rollback = new \RuntimeException('The move is abandoned.');

        try {
            Iam::transaction(function () use ($rollback): never {

                Iam::treeChanges()->changed(self::GRANTED);

                self::assertSame(LinkState::SUSPENDED, $this->link()->state);

                throw $rollback;
            });
        } catch (\RuntimeException $exception) {
            self::assertSame($rollback, $exception);
        }

        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * With SSO's switch off nobody is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithTheSsoSwitchOffNobodyIsReported(): void
    {
        Config::set(SsoSeams::SWITCH, false);

        $reads = 0;

        DB::listen(static function (QueryExecuted $query) use (&$reads): void {
            $reads += str_contains($query->sql, 'authorizable_') ? 1 : 0;
        });

        Iam::transaction(static fn (): int => Iam::treeChanges()->changed(self::GRANTED));

        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertSame(0, $reads);
    }

    /**
     * A move reports people granted in a tenant of another type below.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMoveReportsThePeopleGrantedInATenantOfAnotherTypeBelow(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->app?->instance(TenantResolver::class, new AccountTenancy);

        $account = new Reference(Account::TYPE, Account::PREFIX . '1');
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        StoredTenantTree::place($account, self::organisation(self::GRANTED_CHILD));

        DB::table('authorizable_roles')->where('authorizable_id', self::keyOf($this->person()))->delete();

        $service->grantRole($this->person(), self::ROLE, tenant: $account, includeSubtree: false);

        Iam::transaction(function (): void {

            StoredTenantTree::place(self::organisation(self::GRANTED));

            Iam::treeChanges()->changed(self::GRANTED);
        });

        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
    }

    /**
     * Grant the role to the grantee in the tenant alone.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  string  $tenantId
     * @return void
     *
     * @throws \Throwable
     */
    private function grant(Model $grantee, string $tenantId): void
    {
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        $service->grantRole($grantee, self::ROLE, tenant: self::organisation($tenantId), includeSubtree: false);
    }

    /**
     * The person granted in the granted tenant.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    private function person(): Person
    {
        return $this->person ?? self::fail('No person is arranged.');
    }

    /**
     * The person's link by a verified domain, as stored now.
     *
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function link(): Link
    {
        return Link::query()->findOrFail($this->linkId);
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
     * `laravel-authorization`'s reference to the organisation of the id.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function organisation(string $id): Reference
    {
        return new Reference(Organisation::TYPE, $id);
    }
}
