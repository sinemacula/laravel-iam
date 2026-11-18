<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsRequest;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthenticationEventMapper;
use SineMacula\Laravel\Iam\Authorization\InsufficientAuthenticationMapping;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException as StepUp;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\Enums\ReportPermission;
use Tests\Fixtures\Authorization\ServiceAccount;
use Tests\TestCase;

/**
 * End-to-end tests of a machine signing in with the client credentials grant
 * and calling a `jwt` route with the token it was granted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectResolverAdapter::class)]
#[CoversClass(SessionPolicySourceAdapter::class)]
#[CoversClass(InsufficientAuthenticationMapping::class)]
#[CoversClass(AuthenticationEventMapper::class)]
final class ClientCredentialsTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /** @var string The `jwt` guard machines exchange their keys on. */
    private const string M2M = 'm2m';

    /** @var list<string> Every report permission. */
    private const array REPORTS = ['reports:read', 'reports:export', 'reports:delete'];

    /**
     * Render MFA's step-up as its 401 challenge, as an application does, and
     * declare the report permissions.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $handler = $this->app?->make(ExceptionHandler::class);

        assert($handler instanceof Handler);

        $handler->renderable(static fn (StepUp $exception): JsonResponse => new JsonResponse($exception->toArray(), 401, ['WWW-Authenticate' => $exception->wwwAuthenticate()]));

        foreach (self::REPORTS as $permission) {
            Permission::query()->create(['name' => $permission]);
        }
    }

    /**
     * A token is allowed only the scopes it was granted, of those its account
     * holds, and an action whose allow requires a stronger sign-in is a 403.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testATokensScopesBoundWhatItsAccountMayDo(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $account = $this->account();
        $issued  = Auth::apiKeys(self::M2M)->issue($account, $account, self::REPORTS);
        $fake    = AuditLog::fake();

        $granted = $this->exchange($issued->key()->reveal(), 'reports:read reports:delete')
            ->assertOk()
            ->assertJsonPath('scope', 'reports:read reports:delete');

        $token = $granted->json('access_token');

        self::assertIsString($token);

        $this->request('GET', '/reports', $token)
            ->assertOk()
            ->assertExactJson([
                'manager' => ['reports:read' => true, 'reports:export' => false, 'reports:delete' => false],
                'gate'    => ['reports:read' => true, 'reports:export' => false, 'reports:delete' => false],
            ]);

        $this->request('DELETE', '/reports', $token)->assertForbidden();

        $records = $fake->recorded(static fn (AuditRecord $record): bool => $record->event === 'authentication.client_credentials_granted');

        self::assertCount(1, $records);
        self::assertSame($account->getMorphClass(), $records[0]->actorType);
        self::assertSame((string) $account->id, $records[0]->actorId);
        self::assertSame($issued->summary->id, $records[0]->credentialId);
        self::assertSame(self::M2M, $records[0]->guard);
        self::assertNull($records[0]->sessionId);
        self::assertSame(['scopes' => ['reports:read', 'reports:delete']], $records[0]->properties);
    }

    /**
     * Define the token endpoint and the routes the token is used on.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->post('oauth/token', static fn (Request $request) => Auth::clientCredentials(self::M2M)->exchange(
            ClientCredentialsRequest::extract($request),
            ClientContext::fromRequest($request),
        ));

        $router->get('reports', static fn (): JsonResponse => new JsonResponse([
            'manager' => array_combine(self::REPORTS, array_map(static fn (string $action): bool => Authorization::can($action), self::REPORTS)),
            'gate'    => array_combine(self::REPORTS, array_map(static fn (string $action): bool => Gate::allows($action), self::REPORTS)),
        ]))->middleware('auth:' . self::M2M);

        $router->delete('reports', static function (): JsonResponse {

            Authorization::authorize('reports:delete');

            return new JsonResponse(['deleted' => true]);
        })->middleware('auth:' . self::M2M);
    }

    /**
     * Load the application's configuration, then the guard machines exchange
     * their keys on and the report permissions, before any provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $config = $app->make('config');

        $config->set('auth.guards.' . self::M2M, ['driver' => 'jwt', 'provider' => 'service-accounts', 'application' => ['methods' => ['client_credentials']]]);
        $config->set('auth.providers.service-accounts', ['driver' => 'model', 'model' => ServiceAccount::class]);
        $config->set('authorization.permission_enums', [ReportPermission::class]);
    }

    /**
     * A service account granted reading and exporting, and allowed deleting
     * only on a multifactor sign-in.
     *
     * @return \Tests\Fixtures\Authorization\ServiceAccount
     */
    private function account(): ServiceAccount
    {
        $account = ServiceAccount::query()->create(['name' => 'Reporting']);

        $account->givePermission('reports:read');
        $account->givePermission('reports:export');
        $account->attachPolicy(Policy::query()->create([
            'name'     => 'delete-after-step-up',
            'document' => [
                'statements' => [
                    [
                        'sid'        => 'delete-after-step-up',
                        'effect'     => 'allow',
                        'actions'    => ['reports:delete'],
                        'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => []]]],
                    ],
                ],
            ],
        ]));

        return $account;
    }

    /**
     * Exchange the key for a token over HTTP Basic, asking for the scope.
     *
     * @param  string  $key
     * @param  string  $scope
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function exchange(string $key, string $scope): TestResponse
    {
        $split  = (int) strrpos($key, '_');
        $client = substr($key, 0, $split) . ':' . substr($key, $split + 1);

        return $this->post('/oauth/token', ['grant_type' => 'client_credentials', 'scope' => $scope], ['Authorization' => 'Basic ' . base64_encode($client)]);
    }

    /**
     * Make a request as a new one, with the bearer token and nothing the
     * previous request bound.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function request(string $method, string $uri, string $token): TestResponse
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $auth->forgetGuardState();

        return $this->withToken($token)->json($method, $uri);
    }
}
