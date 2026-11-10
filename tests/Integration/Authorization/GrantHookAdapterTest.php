<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Database\DeadlockException;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;
use SineMacula\Laravel\Authorization\Administration\ConflictRetries;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Exceptions\TransactionConflictException;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;
use SineMacula\Laravel\Authorization\Hooks\ListedGrantHooks;
use SineMacula\Laravel\Authorization\Hooks\ProposedGrant;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\GrantHookAdapter;
use SineMacula\Laravel\Iam\Authorization\IdentityDirectoryAdapter;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Link;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Authorization\PanelAdmin;
use Tests\Fixtures\Authorization\RecordingGrantHook;
use Tests\Fixtures\Authorization\RefusingGrantHook;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authorization`'s grant hook, answered by SSO's
 * scope widening (IAM-6.7, AUTHZ-11.3): a grant that widens a person's scope
 * into a tenant suspends their link by a verified domain in another tenant's
 * connection and revokes the session established through it, inside the grant's
 * own transaction, before the grant is written; a platform-wide grant does so
 * for every tenant, and a grant in the link's own tenant leaves it alone; a
 * grant to a grantee that is not `laravel-authentication`'s identity, which SSO
 * never links, is written with nothing reported to SSO; the hooks the
 * application lists in `authorization.grant_hooks` alongside it run once,
 * before it, as `laravel-authorization` wraps the bound hook in them, and a
 * refusal from either refuses the grant, the adapter's after the listed hooks
 * ran included; a suspension is reported for the client the widening carries,
 * and for none when it carries none; and a grant made inside the application's
 * own transaction is rolled back with it, the suspension included.
 *
 * The grant runs inside `laravel-authorization`'s transaction, where SSO's
 * scope widening takes its identity guard and locks the connections holding the
 * person's links, so each scenario that commits or rolls back runs at the
 * connection's own level on every engine, then at READ COMMITTED and REPEATABLE
 * READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantHookAdapter::class)]
#[CoversClass(IdentityDirectoryAdapter::class)]
#[CoversClass(TenantTranslator::class)]
final class GrantHookAdapterTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople, SignsInThroughLinks {
        SignsInThroughLinks::keyOf insteadof RunsSsoFlows;
        SignsInThroughLinks::referenceOf insteadof RunsSsoFlows;
        SignsInThroughLinks::signInMethods insteadof RunsSsoFlows;
    }

    /** @var string The tenant of the connection the person's link by a verified domain is in. */
    private const string OTHER_TENANT = 'tenant-2';

    /** @var string A third tenant, beyond the link's and the grant's. */
    private const string OTHER_TENANT_BEYOND = 'tenant-3';

    /** @var string The morph type `laravel-authorization` names the tests' tenants by. */
    private const string TENANT_TYPE = 'organisation';

    /** @var string The role granted. */
    private const string ROLE = 'editor';

    /** @var ?\Tests\Fixtures\Models\Person The person granted the role. */
    private ?Person $person = null;

    /** @var string The person's link by a verified domain, in the other tenant's connection. */
    private string $linkId = '';

    /** @var string The other tenant's connection. */
    private string $otherConnectionId = '';

    /**
     * Arrange SSO, store the role, give the person a link by a verified domain
     * in a connection of the other tenant, and resolve every tenant to the
     * organisation of its id.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->app?->instance(TenantResolver::class, new OrganisationTenancy);

        Role::query()->create(['name' => self::ROLE]);

        $this->person            = $this->createPerson();
        $this->otherConnectionId = $this->makeConnection(self::OTHER_TENANT);
        $tenantConnection        = $this->connectionId;
        $this->connectionId      = $this->otherConnectionId;
        $this->linkId            = (string) $this->linkThroughFlow($this->person)->linkId;
        $this->connectionId      = $tenantConnection;

        Link::query()->whereKey($this->linkId)->update(['provenance' => LinkOrigin::VERIFIED_DOMAIN->value]);
    }

    /**
     * The adapter is the grant hook `laravel-authorization` calls.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheAdapterIsTheBoundGrantHook(): void
    {
        self::assertInstanceOf(GrantHookAdapter::class, $this->resolved(GrantHook::class));
    }

    /**
     * A grant in the tenant suspends the person's link by a verified domain in
     * the other tenant's connection and revokes the session established through
     * it, and the grant is written; granted again, nothing more is reported.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAGrantInATenantSuspendsTheLinkInAnotherTenantAndRevokesItsSessions(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->person();
        $session = $this->signInThrough($person, $this->otherConnectionId, $this->linkId);

        $this->grant(self::TENANT);

        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
        self::assertNotNull($this->stored($session)->getRevokedAt());
        self::assertTrue($this->holdsRole(self::TENANT));
    }

    /**
     * A platform-wide grant reaches beyond every tenant, so the link in the
     * other tenant's connection is suspended too.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAPlatformGrantSuspendsTheLink(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->grant(null);

        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
        self::assertTrue($this->holdsRole(null));
    }

    /**
     * A grant in the link's own tenant is inside it: the link is left active,
     * and its session standing.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAGrantInTheLinksOwnTenantLeavesItAlone(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->signInThrough($this->person(), $this->otherConnectionId, $this->linkId);

        $this->grant(self::OTHER_TENANT);

        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertNull($this->stored($session)->getRevokedAt());
        self::assertTrue($this->holdsRole(self::OTHER_TENANT));
    }

    /**
     * A grant in a tenant whose key, resolved as an identifier, names another
     * tenant than the grant does is refused before anything is written: taken
     * on trust, the key would be read as that other tenant, the link's own, and
     * the link left active while the person reaches beyond it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantInATenantThatDoesNotResolveBackIsRefused(): void
    {
        $session = $this->signInThrough($this->person(), $this->otherConnectionId, $this->linkId);
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        try {
            $service->grantRole($this->person(), self::ROLE, tenant: new Reference('another-type', self::OTHER_TENANT), includeSubtree: false);

            self::fail('A grant in a tenant that does not resolve back was written.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(UnresolvedReferenceException::forGrantTenant(self::OTHER_TENANT)->getMessage(), $exception->getMessage());
        }

        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertNull($this->stored($session)->getRevokedAt());
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * Under `laravel-authentication`'s default tenant resolver, which resolves
     * no tenant, a grant in a tenant that widens the person's scope is refused
     * as the grant's tenant, and nothing is written; `iam:check` refuses that
     * resolver while the hook is bound, so a deploy finds it first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantInATenantUnderTheDefaultResolverIsRefusedAsTheGrants(): void
    {
        $this->app?->instance(TenantResolver::class, new ResolveNoTenant);

        try {
            $this->grant(self::TENANT);

            self::fail('A grant in a tenant no resolver resolves was written.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(UnresolvedReferenceException::forGrantTenant(self::TENANT)->getMessage(), $exception->getMessage());
        }

        self::assertFalse($this->holdsRole(self::TENANT));
        self::assertSame(LinkState::ACTIVE, $this->link()->state);
    }

    /**
     * A grant to a grantee that is not `laravel-authentication`'s identity (an
     * admin panel's user, which `laravel-authorization` answers as its own
     * identity) widens nobody SSO links: it is written, platform-wide and in a
     * tenant no resolver resolves alike, with nothing reported to SSO and the
     * person's link left active, and the hooks the application lists still run
     * for it.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAGrantToAGranteeThatIsNoIdentityIsWrittenAndItsHooksRun(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $hook    = new RecordingGrantHook;
        $admin   = PanelAdmin::query()->create(['name' => 'Panel Admin', 'email' => 'admin@example.test']);
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        $this->app->instance(RecordingGrantHook::class, $hook);
        $this->app->instance(TenantResolver::class, new ResolveNoTenant);

        Config::set('authorization.grant_hooks', [RecordingGrantHook::class]);

        $service->grantRole($admin, self::ROLE, tenant: new Reference(self::TENANT_TYPE, self::TENANT), includeSubtree: false);
        $service->grantRole($admin, self::ROLE, includeSubtree: false);

        self::assertCount(2, $hook->widenings);
        self::assertEquals(Reference::of($admin), $hook->widenings[0]->identity);
        self::assertSame(2, DB::table('authorizable_roles')->where('authorizable_type', $admin->getMorphClass())->where('authorizable_id', (string) $admin->id)->count());
        self::assertSame(LinkState::ACTIVE, $this->link()->state);
    }

    /**
     * A widening naming an identity of `laravel-authentication`'s kind whose
     * row cannot be found is refused, never passed over (IAM-8.2).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWideningOfAnIdentityThatCannotBeFoundIsRefused(): void
    {
        $hook     = $this->resolved(GrantHook::class);
        $identity = new Reference($this->person()->getMorphClass(), '999999');
        $grant    = new ProposedGrant('authorization:role.grant', new Reference('role', '1'), null, null, false, null);

        self::assertInstanceOf(GrantHookAdapter::class, $hook);

        $this->expectException(UnresolvedReferenceException::class);

        Iam::transaction(static fn () => $hook->beforeWidening(self::widening($identity, [$grant])));
    }

    /**
     * A widening whose grants hold in more than one tenant is reported for each
     * of them: one in the link's own tenant alone leaves the link active, and
     * one beside it in another tenant, named after the first is named again,
     * suspends it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryTenantTheWideningGrantsHoldInIsReported(): void
    {
        $hook     = $this->resolved(GrantHook::class);
        $identity = Reference::of($this->person());
        $own      = new ProposedGrant('authorization:role.grant', new Reference('role', '1'), new Reference(self::TENANT_TYPE, self::OTHER_TENANT), null, false, null);
        $other    = new ProposedGrant('authorization:role.grant', new Reference('role', '1'), new Reference(self::TENANT_TYPE, self::TENANT), null, false, null);

        self::assertInstanceOf(GrantHookAdapter::class, $hook);

        Iam::transaction(static fn () => $hook->beforeWidening(self::widening($identity, [$own, $own])));

        self::assertSame(LinkState::ACTIVE, $this->link()->state);

        Iam::transaction(static fn () => $hook->beforeWidening(self::widening($identity, [$own, $own, $other])));

        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
    }

    /**
     * Rows of the client a widening carries, as its operation's IP address and
     * user agent: a request's, and none, as a trusted, console or queued call
     * carries.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideClients(): iterable
    {
        yield 'a request\'s client' => [self::CLIENT_IP, self::CLIENT_AGENT];

        yield 'no client' => [null, null];
    }

    /**
     * The suspension a widening causes is reported for the client the widening
     * carries, its operation's, and for none when it carries none.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideClients')]
    public function testASuspensionIsReportedForTheWideningsClient(?string $ip, ?string $userAgent): void
    {
        $hook      = $this->resolved(GrantHook::class);
        $identity  = Reference::of($this->person());
        $grant     = new ProposedGrant('authorization:role.grant', new Reference('role', '1'), new Reference(self::TENANT_TYPE, self::TENANT), null, false, null);
        $operation = new Operation('operation-1', null, new \DateTimeImmutable, ip: $ip, userAgent: $userAgent);

        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\LinkSuspended> $suspended */
        $suspended = new \ArrayObject;

        Event::listen(LinkSuspended::class, static function (LinkSuspended $event) use ($suspended): void {
            $suspended->append($event);
        });

        self::assertInstanceOf(GrantHookAdapter::class, $hook);

        Iam::transaction(static fn () => $hook->beforeWidening(GrantWidening::of($operation, $identity, $identity, [$grant], new \DateTimeImmutable)));

        $context = ($suspended[0] ?? self::fail('No suspension was reported.'))->context;

        self::assertCount(1, $suspended);
        self::assertSame([$ip, $userAgent], [$context->ip, $context->userAgent]);
    }

    /**
     * A hook the application lists in `authorization.grant_hooks` once the
     * application has booted still runs, once, beside SSO's widening, and is
     * handed the widening of the grant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHookTheApplicationListsStillRunsBesideTheWidening(): void
    {
        $hook = new RecordingGrantHook;

        $this->app?->instance(RecordingGrantHook::class, $hook);

        Config::set('authorization.grant_hooks', [RecordingGrantHook::class]);

        $this->grant(self::TENANT);

        self::assertCount(1, $hook->widenings);
        self::assertEquals(Reference::of($this->person()), $hook->widenings[0]->identity);
        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
    }

    /**
     * A refusal from a hook the application lists refuses the grant: nothing is
     * written, suspended or revoked.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusalFromAListedHookRefusesTheGrant(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->signInThrough($this->person(), $this->otherConnectionId, $this->linkId);

        Config::set('authorization.grant_hooks', [RefusingGrantHook::class]);

        try {
            $this->grant(self::TENANT);

            self::fail('A grant the application refused was written.');
        } catch (\RuntimeException $exception) {
            self::assertSame(RefusingGrantHook::MESSAGE, $exception->getMessage());
        }

        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertNull($this->stored($session)->getRevokedAt());
        self::assertFalse($this->holdsRole(self::TENANT));
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * An application that lists its own grant hooks in its configuration, read
     * as `laravel-authorization` registers, has them run alongside the adapter:
     * the hook resolved is the adapter wrapped in the listed hooks, which run
     * once, before it, and the grant is written with the link suspended.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    #[WithConfig('authorization.grant_hooks', [RecordingGrantHook::class], defer: false)]
    public function testTheHooksTheApplicationListsRunOnceBeforeTheAdapter(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $listed = new RecordingGrantHook;

        $this->app?->instance(RecordingGrantHook::class, $listed);

        self::assertInstanceOf(ListedGrantHooks::class, $this->resolved(GrantHook::class));

        $this->grant(self::TENANT);

        self::assertCount(1, $listed->widenings);
        self::assertEquals(Reference::of($this->person()), $listed->widenings[0]->identity);
        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
        self::assertTrue($this->holdsRole(self::TENANT));
    }

    /**
     * The adapter's refusal, after the hooks the application lists have run,
     * still refuses the grant: the listed hook was handed the widening first,
     * and nothing is written, suspended or revoked.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    #[WithConfig('authorization.grant_hooks', [RecordingGrantHook::class], defer: false)]
    public function testTheAdaptersRefusalAfterTheListedHooksRefusesTheGrant(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $listed  = new RecordingGrantHook;
        $session = $this->signInThrough($this->person(), $this->otherConnectionId, $this->linkId);

        $this->app?->instance(RecordingGrantHook::class, $listed);
        $this->app?->instance(TenantResolver::class, new ResolveNoTenant);

        try {
            $this->grant(self::TENANT);

            self::fail('A grant the adapter refused was written.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(UnresolvedReferenceException::forGrantTenant(self::TENANT)->getMessage(), $exception->getMessage());
        }

        self::assertCount(1, $listed->widenings);
        self::assertFalse($this->holdsRole(self::TENANT));
        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertNull($this->stored($session)->getRevokedAt());
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * A grant made inside the application's own transaction on the storage
     * connection is rolled back with it, and the suspension with it.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAGrantInsideTheApplicationsTransactionRollsBackWithIt(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $rollback = new \RuntimeException('The rest of the change could not be written.');

        try {
            Iam::transaction(function () use ($rollback): never {
                $this->grant(self::TENANT);

                self::assertSame(LinkState::SUSPENDED, $this->link()->state, 'The widening was not reported inside the grant\'s transaction.');

                throw $rollback;
            });
        } catch (\RuntimeException $exception) {
            self::assertSame($rollback, $exception);
        }

        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertFalse($this->holdsRole(self::TENANT));
    }

    /**
     * SSO's refusal of a widening whose link candidates changed under its lock
     * is handed to `laravel-authorization` as a concurrency error, SSO's
     * refusal kept as its cause: one its conflict retries try a delegated call
     * again for, and turn into `TransactionConflictException` inside the
     * application's transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLinkCandidatesThatChangedAreAConcurrencyError(): void
    {
        $this->changeLinkCandidatesOnce();

        $hook     = $this->resolved(GrantHook::class);
        $identity = Reference::of($this->person());
        $grant    = new ProposedGrant('authorization:role.grant', new Reference('role', '1'), new Reference(self::TENANT_TYPE, self::TENANT), null, false, null);

        self::assertInstanceOf(GrantHookAdapter::class, $hook);

        try {
            DB::transaction(static fn () => $hook->beforeWidening(self::widening($identity, [$grant])));

            self::fail('A widening whose link candidates changed was reported.');
        } catch (DeadlockException $exception) {
            self::assertTrue(ConflictRetries::isConcurrencyError($exception));
            self::assertSame(TransactionConflictException::SERIALIZATION_FAILURE, $exception->getCode());
            self::assertInstanceOf(LinkCandidatesChanged::class, $exception->getPrevious());
        }

        self::assertSame(LinkState::ACTIVE, $this->link()->state);
    }

    /**
     * A grant whose link candidates changed, made inside a transaction that is
     * tried again on a concurrency error, is written by the try after it: the
     * application's `DB::transaction()` given attempts, as this package's
     * transaction is.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAGrantWhoseLinkCandidatesChangedIsTriedAgainWithItsTransaction(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $tries = $this->changeLinkCandidatesOnce();

        DB::transaction(fn () => $this->grant(self::TENANT), 2);

        self::assertCount(2, $tries);
        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
        self::assertTrue($this->holdsRole(self::TENANT));

        $tries = $this->changeLinkCandidatesOnce();

        Iam::transaction(fn () => $this->grant(self::OTHER_TENANT_BEYOND));

        self::assertCount(2, $tries);
        self::assertTrue($this->holdsRole(self::OTHER_TENANT_BEYOND));
    }

    /**
     * The widening of the grants given for the identity, as a trusted call
     * proposes it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $identity
     * @param  list<\SineMacula\Laravel\Authorization\Hooks\ProposedGrant>  $changes
     * @return \SineMacula\Laravel\Authorization\Hooks\GrantWidening
     */
    private static function widening(Reference $identity, array $changes): GrantWidening
    {
        return GrantWidening::of(new Operation('operation-1', null, new \DateTimeImmutable), $identity, $identity, $changes, new \DateTimeImmutable);
    }

    /**
     * Have SSO refuse the first widening as one whose link candidates changed,
     * and widen as it would every one after it; answer how many widenings were
     * asked for.
     *
     * @return \ArrayObject<int, true>
     */
    private function changeLinkCandidatesOnce(): \ArrayObject
    {
        $app      = $this->app ?? self::fail('The application has not booted.');
        $tries    = new \ArrayObject;
        $widening = $app->make(ScopeWidening::class);

        $app->bind(ScopeWidening::class, static function () use ($tries, $widening): ScopeWidening {
            $tries->append(true);

            return $tries->count() === 1 ? throw LinkCandidatesChanged::retryWhole() : $widening;
        });

        return $tries;
    }

    /**
     * Grant the person the role in the tenant given, or platform-wide.
     *
     * @param  ?string  $tenantId
     * @return void
     *
     * @throws \Throwable
     */
    private function grant(?string $tenantId): void
    {
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        $service->grantRole($this->person(), self::ROLE, tenant: $tenantId === null ? null : new Reference(self::TENANT_TYPE, $tenantId), includeSubtree: false);
    }

    /**
     * Whether the person holds the role in the tenant given, or platform-wide.
     *
     * @param  ?string  $tenantId
     * @return bool
     */
    private function holdsRole(?string $tenantId): bool
    {
        return DB::table('authorizable_roles')
            ->where('authorizable_type', $this->person()->getMorphClass())
            ->where('authorizable_id', (string) $this->person()->id)
            ->where('tenant_id', $tenantId)
            ->exists();
    }

    /**
     * The person granted the role.
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
     * What the container resolves the abstract to, as anything that asks for it
     * does.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }
}
