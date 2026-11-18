<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Gate;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\Member;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\TestCase;

/**
 * End-to-end tests of a grant in one tenant over HTTP: a member granted a
 * permission in a tenant is allowed it on a session acting there, through the
 * manager and the Gate alike, and refused it on its own session acting in
 * another tenant, the refusal recorded under that tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectResolverAdapter::class)]
#[CoversClass(TenantTranslator::class)]
final class TenantGrantsOverHttpTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /** @var string The tenant the grant is made in. */
    private const string GRANTED = 'org-a';

    /** @var string A tenant the member holds no grant in. */
    private const string OTHER = 'org-b';

    /**
     * Resolve every tenant to the organisation of its id, open to anyone.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->singleton(TenantResolver::class, OrganisationTenancy::class);
        $this->app?->singleton(TenantAccess::class, OrganisationTenancy::class);
    }

    /**
     * A permission granted in one tenant allows the session acting there and
     * denies the same member's session acting in another, recorded there.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAGrantInOneTenantAllowsOnlyTheSessionActingThere(?string $level): void
    {
        self::runAtIsolationLevel($level);

        Permission::query()->create(['name' => InvoicePermission::REFUND->value]);

        $member = Member::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test', 'password' => self::PASSWORD]);

        $member->givePermission(InvoicePermission::REFUND->value, tenant: new Reference(Organisation::TYPE, self::GRANTED));

        $granted = $this->signIn($member, self::GRANTED);
        $other   = $this->signIn($member, self::OTHER);
        $fake    = AuditLog::fake();

        $this->request($granted)->assertOk()->assertExactJson(['manager' => true, 'gate' => true]);

        self::assertSame([], self::denials($fake->recorded()));

        $this->request($other)->assertOk()->assertExactJson(['manager' => false, 'gate' => false]);

        $denials = self::denials($fake->recorded());

        self::assertCount(2, $denials);

        foreach ($denials as $denial) {
            self::assertSame(Outcome::DENIED->value, $denial->outcome);
            self::assertSame(InvoicePermission::REFUND->value, $denial->properties['action'] ?? null);
            self::assertSame([References::TENANT_TYPE, self::OTHER], [$denial->tenantType, $denial->tenantId]);
            self::assertSame((string) $member->getKey(), $denial->actorId);
        }
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
     * The denials among the records.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\AuditRecord>  $records
     * @return list<\SineMacula\Laravel\AuditLog\Records\AuditRecord>
     */
    private static function denials(array $records): array
    {
        return array_values(array_filter($records, static fn (AuditRecord $record): bool => $record->event === 'authorization.access_denied'));
    }

    /**
     * Sign the member in with their password into the tenant, and return the
     * session's access token.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $member
     * @param  string  $tenant
     * @return string
     *
     * @throws \Throwable
     */
    private function signIn(Member $member, string $tenant): string
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $client = new SignInContext(new ClientContext('192.0.2.10', 'iam-tests'), tenant: TenantSelection::of($tenant));
        $result = $auth->sessions(self::GUARD)->signIn('password', ['email' => $member->email, 'password' => self::PASSWORD], $client);

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
