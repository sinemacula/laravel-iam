<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;
use SineMacula\Laravel\Authorization\Contracts\ScopeRegistry as AuthorizationScopeRegistry;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Iam\Authorization\ScopeRegistryAdapter;
use Tests\Concerns\MigratesAuthorization;
use Tests\Fixtures\Authorization\Enums\ReportPermission;
use Tests\Fixtures\Authorization\ServiceAccount;
use Tests\TestCase;

/**
 * Integration tests for the scope registry answered from authorization's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ScopeRegistryAdapter::class)]
final class ScopeRegistryAdapterTest extends TestCase
{
    use MigratesAuthorization;

    /** @var string The guard service accounts authenticate on with an API key. */
    private const string KEYS = 'keys';

    /**
     * Bind the registry and declare the service account guard.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $config = $this->app?->make('config');

        $config?->set('auth.guards.' . self::KEYS, ['driver' => 'api_key', 'provider' => 'service-accounts', 'application' => ['methods' => ['api_key']]]);
        $config?->set('auth.providers.service-accounts', ['driver' => 'model', 'model' => ServiceAccount::class]);

        $this->app?->bind(ScopeRegistry::class, ScopeRegistryAdapter::class);
    }

    /**
     * Rows of `[scopes]` a credential may carry.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideGrantableScopes(): iterable
    {
        yield 'none' => [[]];

        yield 'declared permissions' => [['reports:read', 'reports:export']];

        yield 'a pattern covering declared permissions' => [['reports:*']];

        yield 'a scope the map names' => [['reporting']];
    }

    /**
     * A key is issued with scopes that name real permissions.
     *
     * @param  list<string>  $scopes
     * @return void
     */
    #[DataProvider('provideGrantableScopes')]
    public function testAKeyIsIssuedWithScopesNamingRealPermissions(array $scopes): void
    {
        $account = $this->createAccount();

        $issued = Auth::apiKeys(self::KEYS)->issue($account, $account, $scopes);

        self::assertSame($scopes, $issued->summary->scopes);
    }

    /**
     * Rows of `[scopes asked, scopes refused]`.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>}>
     */
    public static function provideRefusedScopes(): iterable
    {
        yield 'a permission nobody declares' => [['reports:read', 'payroll:read'], ['payroll:read']];

        yield 'a pattern covering none' => [['payroll:*', 'reports:export'], ['payroll:*']];

        yield 'every scope' => [['payroll:read', 'billing'], ['payroll:read', 'billing']];
    }

    /**
     * A key with a scope naming no permission is refused.
     *
     * @param  list<string>  $scopes
     * @param  list<string>  $refused
     * @return void
     */
    #[DataProvider('provideRefusedScopes')]
    public function testAKeyWithAScopeNamingNoPermissionIsRefused(array $scopes, array $refused): void
    {
        $account = $this->createAccount();

        try {
            Auth::apiKeys(self::KEYS)->issue($account, $account, $scopes);

            self::fail('The key was issued.');
        } catch (InvalidScopeException $exception) {
            self::assertSame($refused, $exception->scopes);
        }

        self::assertSame([], Auth::apiKeys(self::KEYS)->keys($account));
    }

    /**
     * The registry rejects each scope authorization does not accept.
     *
     * @return void
     */
    public function testTheRegistryRejectsEachScopeAuthorizationDoesNotAccept(): void
    {
        $registry = $this->registry();

        self::assertInstanceOf(ScopeRegistryAdapter::class, $registry);
        self::assertSame(['billing', 'payroll:read'], $registry->rejected(self::KEYS, $this->createAccount(), ['billing', 'reports:read', 'payroll:read', 'reporting']));
        self::assertSame(['billing', 'payroll:read'], $registry->rejected(self::GUARD, $this->createAccount('Billing'), ['billing', 'reports:read', 'payroll:read', 'reporting']));
    }

    /**
     * The application's own authorization registry is asked.
     *
     * @return void
     */
    public function testTheApplicationsOwnAuthorizationRegistryIsAsked(): void
    {
        $registry = $this->registry();

        self::assertInstanceOf(ScopeRegistryAdapter::class, $registry);

        $this->app?->instance(AuthorizationScopeRegistry::class, new class implements AuthorizationScopeRegistry {
            /**
             * Accept only `billing`.
             *
             * @param  string  $scope
             * @return bool
             */
            #[\Override]
            public function isValid(string $scope): bool
            {
                return $scope === 'billing';
            }

            /**
             * Only `billing`.
             *
             * @return list<string>
             */
            #[\Override]
            public function scopes(): array
            {
                return ['billing'];
            }
        });

        self::assertSame(['reports:read'], $registry->rejected(self::KEYS, $this->createAccount(), ['billing', 'reports:read']));
    }

    /**
     * A rotation holds the scopes to the registry again.
     *
     * @return void
     */
    public function testARotationHoldsTheScopesToTheRegistryAgain(): void
    {
        $account = $this->createAccount();
        $issued  = Auth::apiKeys(self::KEYS)->issue($account, $account, ['reporting']);

        $this->app?->make('config')->set('authorization.session.scopes', []);
        $this->app?->forgetScopedInstances();

        $this->expectException(InvalidScopeException::class);

        Auth::apiKeys(self::KEYS)->rotate($account, $issued->id);
    }

    /**
     * Declare the permissions and scope map.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $config = $app->make('config');

        $config->set('authorization.permission_enums', [ReportPermission::class]);
        $config->set('authorization.session', ['source' => NoSessionPolicy::class, 'scopes' => ['reporting' => ['reports:read', 'reports:export']]]);
    }

    /**
     * The scope registry the container builds.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\ScopeRegistry
     */
    private function registry(): ScopeRegistry
    {
        return $this->app?->make(ScopeRegistry::class) ?? self::fail('The application has not booted.');
    }

    /**
     * Create a service account.
     *
     * @param  string  $name
     * @return \Tests\Fixtures\Authorization\ServiceAccount
     */
    private function createAccount(string $name = 'Reporting'): ServiceAccount
    {
        return ServiceAccount::query()->create(['name' => $name]);
    }
}
