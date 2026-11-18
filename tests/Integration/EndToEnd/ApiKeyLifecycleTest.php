<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Iam\Audit\AuthenticationActorReader;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthenticationEventMapper;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Enums\ReportPermission;
use Tests\Fixtures\Authorization\ServiceAccount;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * End-to-end tests of an API key issued, used, rotated and revoked over HTTP,
 * and the audit trail each step leaves.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationEventMapper::class)]
#[CoversClass(AuthenticationActorReader::class)]
final class ApiKeyLifecycleTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The `api_key` guard service accounts present their keys on. */
    private const string KEYS = 'keys';

    /** @var string The code a request made with a key records. */
    private const string VIEWED = 'iam_test.reports_viewed';

    /** @var int The seconds a rotated key keeps working. */
    private const int OVERLAP = 60;

    /**
     * Declare the permission the keys are scoped to.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Permission::query()->create(['name' => 'reports:read']);
    }

    /**
     * A key managed by a person is recorded under them, each request made with
     * it names it, and a rotated or revoked key is refused with no actor.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAKeysLifecycleLeavesItsTrail(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $account = ServiceAccount::query()->create(['name' => 'Reporting']);
        $token   = $this->signIn($person)->tokens->accessToken->reveal();
        $fake    = AuditLog::fake();

        $issued = $this->request('POST', '/accounts/' . $account->id . '/keys', $token)->assertCreated();
        $first  = self::keyOf($issued);

        $this->request('GET', '/reports', $first['key'])->assertOk();

        $rotated = $this->request('POST', '/accounts/' . $account->id . '/keys/' . $first['id'] . '/rotate', $token)->assertCreated();
        $second  = self::keyOf($rotated);

        $this->request('GET', '/reports', $first['key'])->assertOk();

        $this->travel(self::OVERLAP + 1)->seconds();

        $this->request('GET', '/reports', $first['key'])->assertUnauthorized();
        $this->request('GET', '/reports', $second['key'])->assertOk();

        $this->request('DELETE', '/accounts/' . $account->id . '/keys/' . $second['id'], $token)->assertNoContent();

        $this->request('GET', '/reports', $second['key'])->assertUnauthorized();

        $caller = [self::pair($person), self::pair($person), null, self::KEYS];
        $used   = [self::pair($account), self::pair($account)];
        $owner  = ['key_principal_type' => $account->getMorphClass(), 'key_principal_id' => (string) $account->id];
        $scopes = ['reports:read'];

        self::assertSame([
            ['authentication.api_key_issued', 'success', null, ...$caller, ['scopes' => $scopes, 'key_id' => $first['id'], ...$owner]],
            [self::VIEWED, 'success', null, ...$used, $first['id'], self::KEYS, null],
            ['authentication.api_key_rotated', 'success', null, ...$caller, ['scopes' => $scopes, 'previous_key_id' => $first['id'], 'key_id' => $second['id'], ...$owner]],
            [self::VIEWED, 'success', null, ...$used, $first['id'], self::KEYS, null],
            ['authentication.api_key_rejected', 'failure', 'credential_expired', [null, null], [null, null], $first['id'], self::KEYS, ['method' => 'api_key']],
            [self::VIEWED, 'success', null, ...$used, $second['id'], self::KEYS, null],
            ['authentication.api_key_revoked', 'success', null, ...$caller, ['scopes' => $scopes, 'key_id' => $second['id'], ...$owner]],
            ['authentication.api_key_rejected', 'failure', 'credential_revoked', [null, null], [null, null], $second['id'], self::KEYS, ['method' => 'api_key']],
        ], self::sequence($fake));
    }

    /**
     * Define the routes a person manages a service account's keys on, and the
     * route a service account calls with one.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->post('accounts/{account}/keys', static function (string $account): Response {

            $machine = ServiceAccount::query()->findOrFail($account);
            $issued  = Auth::apiKeys(self::KEYS)->issue($machine, $machine, ['reports:read']);

            return SecretResponse::json(['id' => $issued->summary->id, 'key' => $issued->key()], 201);
        })->middleware('auth:' . self::GUARD);

        $router->post('accounts/{account}/keys/{key}/rotate', static function (string $account, string $key): Response {

            $issued = Auth::apiKeys(self::KEYS)->rotate(ServiceAccount::query()->findOrFail($account), $key, self::OVERLAP) ?? abort(404);

            return SecretResponse::json(['id' => $issued->summary->id, 'key' => $issued->key()], 201);
        })->middleware('auth:' . self::GUARD);

        $router->delete('accounts/{account}/keys/{key}', static function (string $account, string $key): Response {

            $revoked = Auth::apiKeys(self::KEYS)->revoke(ServiceAccount::query()->findOrFail($account), $key);

            return new Response(status: $revoked ? 204 : 404);
        })->middleware('auth:' . self::GUARD);

        $router->get('reports', static function (): JsonResponse {

            AuditLog::record(self::VIEWED);

            return new JsonResponse(['viewed' => true]);
        })->middleware('auth:' . self::KEYS);
    }

    /**
     * Load the application's configuration, then the guard service accounts
     * present their keys on and the report permissions, before any provider
     * registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $config = $app->make('config');

        $config->set('auth.guards.' . self::KEYS, ['driver' => 'api_key', 'provider' => 'service-accounts', 'application' => ['methods' => ['api_key']]]);
        $config->set('auth.providers.service-accounts', ['driver' => 'model', 'model' => ServiceAccount::class]);
        $config->set('authorization.permission_enums', [ReportPermission::class]);
    }

    /**
     * Make a request as a new one, with the bearer credential and nothing the
     * previous request bound.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  string  $credential
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function request(string $method, string $uri, string $credential): TestResponse
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $auth->forgetGuardState();

        return $this->withToken($credential)->json($method, $uri);
    }

    /**
     * The id and key a response issued.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @return array{id: string, key: string}
     */
    private static function keyOf(TestResponse $response): array
    {
        $id  = $response->json('id');
        $key = $response->json('key');

        self::assertIsString($id);
        self::assertIsString($key);

        return ['id' => $id, 'key' => $key];
    }

    /**
     * A model's type and key, as a record names it.
     *
     * @param  \Tests\Fixtures\Authorization\ServiceAccount|\Tests\Fixtures\Models\Person  $model
     * @return list<string>
     */
    private static function pair(Person|ServiceAccount $model): array
    {
        return [$model->getMorphClass(), (string) $model->id];
    }

    /**
     * Every record the fake holds, in order, as its outcome, actor, principal,
     * credential, guard and properties.
     *
     * @param  \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore  $fake
     * @return list<list<mixed>>
     */
    private static function sequence(FakeAuditStore $fake): array
    {
        return array_map(static fn (AuditRecord $record): array => [
            $record->event,
            $record->outcome,
            $record->reason,
            [$record->actorType, $record->actorId],
            [$record->principalType, $record->principalId],
            $record->credentialId,
            $record->guard,
            $record->properties,
        ], $fake->recorded());
    }
}
