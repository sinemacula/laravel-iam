<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Gate;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Iam\Contracts\GroupResync;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Provisioning\GroupGrants;
use SineMacula\Laravel\Iam\Provisioning\MappedGroupResync;
use SineMacula\Laravel\Iam\Testing\FakeGroupMapping;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\Member;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Provisioning\ProvisionedMembership;
use Tests\TestCase;

/**
 * End-to-end tests of the roles a provider's groups map to over HTTP: a first
 * SSO sign-in into the connection's tenant is provisioned a member whose new
 * session is allowed the mapped role's action, and once a later sign-in
 * without the group re-syncs the roles, every session of theirs is refused it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GroupGrants::class)]
#[CoversClass(MappedGroupResync::class)]
final class GroupRolesOverHttpTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The role the finance operations group gives. */
    private const string APPROVER = 'invoices.approver';

    /**
     * Arrange SSO, store the approver role allowed a refund, provision members,
     * map the group, re-sync it, and open every tenant to anyone.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        Permission::query()->create(['name' => InvoicePermission::REFUND->value]);
        Role::query()->create(['name' => self::APPROVER]);

        $this->app?->make(RoleService::class)->grantPermission(self::APPROVER, InvoicePermission::REFUND->value);

        $this->app?->instance(TenantResolver::class, new OrganisationTenancy);
        $this->app?->instance(TenantAccess::class, new OrganisationTenancy);
        $this->app?->instance(Provisioner::class, self::provisionsMembers());
        $this->app?->bind(GroupResync::class, MappedGroupResync::class);

        FakeGroupMapping::fake($this->app)->map('finance-ops', self::APPROVER);
    }

    /**
     * A first sign-in's mapped role allows its session the role's action in
     * the connection's tenant, and a re-sync without the group refuses it.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMappedRoleAllowsTheSessionUntilAReSyncRemovesIt(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $first = $this->signInWith(['finance-ops']);

        $this->request($first)->assertOk()->assertExactJson(['manager' => true, 'gate' => true]);

        $later = $this->signInWith(['engineering']);

        $this->request($later)->assertOk()->assertExactJson(['manager' => false, 'gate' => false]);
        $this->request($first)->assertOk()->assertExactJson(['manager' => false, 'gate' => false]);
    }

    /**
     * Define the route the checks are made on, on the stateless guard.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->get('can', static fn (): JsonResponse => new JsonResponse([
            'manager' => Authorization::can(InvoicePermission::REFUND->value),
            'gate'    => Gate::allows(InvoicePermission::REFUND->value),
        ]))->middleware('auth:' . self::GUARD);
    }

    /**
     * Sign members in on the guard people sign in on, and declare the invoice
     * permissions, before any provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $config = $app->make('config');

        $config->set('auth.providers.people', ['driver' => 'model', 'model' => Member::class]);
        $config->set('authorization.permission_enums', [InvoicePermission::class]);
    }

    /**
     * A provisioner of members, the grantees `laravel-authorization` reads
     * roles of.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\Provisioner
     */
    private static function provisionsMembers(): Provisioner
    {
        return new class implements Provisioner {
            /**
             * A new member, under an email address no other member has.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \Tests\Fixtures\Authorization\Member
             *
             * @throws \Random\RandomException
             */
            #[\Override]
            public function createIdentity(#[\SensitiveParameter] VerifiedResult $result): Identity
            {
                return Member::query()->create(['name' => 'Provisioned member', 'email' => sprintf('provisioned-%s@people.test', bin2hex(random_bytes(8)))]);
            }

            /**
             * Record the member's membership of the tenant.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
             * @param  string  $tenantId
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return void
             */
            #[\Override]
            public function createMembership(Identity $identity, string $tenantId, #[\SensitiveParameter] VerifiedResult $result): void
            {
                assert($identity instanceof Member);

                ProvisionedMembership::query()->create(['person_id' => $identity->getKey(), 'tenant_id' => $tenantId]);
            }
        };
    }

    /**
     * Sign in through SSO into the connection's tenant, the provider reporting
     * the groups, and return the session's access token.
     *
     * @param  list<string>  $groups
     * @return string
     *
     * @throws \Throwable
     */
    private function signInWith(array $groups): string
    {
        $handoff = $this->handoff(Purpose::SIGN_IN, null, null, static fn (FakeIdToken $token): FakeIdToken => $token->with('groups', $groups));
        $context = new SignInContext(self::client(), tenant: TenantSelection::of(self::TENANT));
        $result  = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, $context);

        self::assertInstanceOf(SignInResult::class, $result);
        self::assertTrue($result->isSignedIn());
        self::assertNotNull($result->session);

        return $result->session->tokens->accessToken->reveal();
    }

    /**
     * Ask the route as a new request with the bearer token, nothing the
     * previous request bound or scoped.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function request(string $token): TestResponse
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $auth->forgetGuardState();

        // A new request starts with no scoped instance, the resolved tenant too.
        $this->app?->forgetScopedInstances();

        return $this->withToken($token)->getJson('/can');
    }
}
