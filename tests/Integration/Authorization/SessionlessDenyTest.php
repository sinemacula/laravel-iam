<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextAdapter;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\Member;
use Tests\Fixtures\Authorization\ServiceAccount;
use Tests\TestCase;

/**
 * Integration tests of a deny conditioned on the authentication context's
 * session (IAM-6.2), as the authorization guide describes it: the context
 * always describes the request's own caller, never the subject a check names,
 * so a deny that applies where `authentication.session_id` is absent refuses
 * the caller's own sessionless checks (a machine on its API key, and a check
 * made outside any request, as a queued job's is, whose context is empty), yet
 * never refuses a check about a principal the caller names
 * (`Authorization::for()`, `Gate::forUser()`) while the caller holds a session,
 * though that principal holds no session of its own.
 *
 * The member's session and the machine's key are real ones, issued by
 * `laravel-authentication`, so it runs at the connection's own level on every
 * engine, then at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationContextAdapter::class)]
final class SessionlessDenyTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /** @var string The action a deny refuses wherever the context names no session. */
    private const string REFUND = 'invoices:refund';

    /** @var string The action nothing denies. */
    private const string VOID = 'invoices:void';

    /** @var string The guard service accounts authenticate on with an API key. */
    private const string KEYS = 'keys';

    /**
     * The deny refuses a machine on its key and a check made outside any
     * request, but not a check about a principal named by a caller holding a
     * session, through the manager or the Gate.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testADenyOnTheContextsSessionRefusesOnlyTheCallersOwnSessionlessChecks(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $caller = $this->member('ada@example.test');
        $named  = $this->member('grace@example.test');

        self::assertFalse(Authorization::for($named)->can(self::REFUND));
        self::assertTrue(Authorization::for($named)->can(self::VOID));

        $token = $this->signIn($caller);

        $this->request('/named', $token, ['member' => $named->getKey()])
            ->assertOk()
            ->assertExactJson(['own' => true, 'named' => true, 'gate' => true]);

        $key = $this->machineKey();

        $this->request('/machine', $key)->assertOk()->assertExactJson([self::REFUND => false, self::VOID => true]);
    }

    /**
     * Define the routes the requests are made to: one a member signed in with a
     * session asks on, about itself and about a member it names, and one a
     * machine asks on with its API key.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->post('named', static function (Request $request): JsonResponse {

            $named = Member::query()->findOrFail($request->integer('member'));

            return new JsonResponse([
                'own'   => Authorization::can(self::REFUND),
                'named' => Authorization::for($named)->can(self::REFUND),
                'gate'  => Gate::forUser($named)->allows(self::REFUND),
            ]);
        })->middleware('auth:' . self::GUARD);

        $router->post('machine', static fn (): JsonResponse => new JsonResponse([
            self::REFUND => Authorization::can(self::REFUND),
            self::VOID   => Authorization::can(self::VOID),
        ]))->middleware('auth:' . self::KEYS);
    }

    /**
     * Load the application's configuration, then sign members in on the guard
     * people sign in on, authenticate service accounts on an API key guard, and
     * declare the invoice permissions, set before any provider registers.
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
        $config->set('auth.guards.' . self::KEYS, ['driver' => 'api_key', 'provider' => 'service-accounts', 'application' => ['methods' => ['api_key']]]);
        $config->set('auth.providers.service-accounts', ['driver' => 'model', 'model' => ServiceAccount::class]);
        $config->set('authorization.permission_enums', [InvoicePermission::class]);
    }

    /**
     * The policy allowing both invoice actions and denying a refund wherever
     * the authentication context names no session, as the guide suggests.
     *
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(): Policy
    {
        return Policy::query()->firstOrCreate(['name' => 'refunds-in-a-session'], [
            'document' => [
                'statements' => [
                    [
                        'sid'     => 'allow-invoices',
                        'effect'  => 'allow',
                        'actions' => [self::REFUND, self::VOID],
                    ],
                    [
                        'sid'        => 'deny-refund-without-a-session',
                        'effect'     => 'deny',
                        'actions'    => [self::REFUND],
                        'conditions' => ['null' => ['authentication.session_id' => true]],
                    ],
                ],
            ],
        ]);
    }

    /**
     * A member attached to the policy.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Authorization\Member
     */
    private function member(string $email): Member
    {
        $member = Member::query()->create(['name' => 'Ada Lovelace', 'email' => $email, 'password' => self::PASSWORD]);

        $member->attachPolicy(self::policy());

        return $member;
    }

    /**
     * A service account attached to the policy, and an API key issued to it on
     * the keys guard with scopes covering both invoice actions.
     *
     * @return string
     */
    private function machineKey(): string
    {
        $account = ServiceAccount::query()->create(['name' => 'Billing']);

        $account->attachPolicy(self::policy());

        return Auth::apiKeys(self::KEYS)->issue($account, $account, [self::REFUND, self::VOID])->key()->reveal();
    }

    /**
     * Sign the member in with their password, and return the session's access
     * token.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $member
     * @return string
     *
     * @throws \Throwable
     */
    private function signIn(Member $member): string
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $client = new SignInContext(new ClientContext('192.0.2.10', 'iam-tests'));
        $result = $auth->sessions(self::GUARD)->signIn('password', ['email' => $member->email, 'password' => self::PASSWORD], $client);

        self::assertTrue($result->isSignedIn());
        self::assertNotNull($result->session);

        return $result->session->tokens->accessToken->reveal();
    }

    /**
     * Make a request as a new one, with the bearer credential and nothing the
     * previous request bound.
     *
     * @param  string  $uri
     * @param  string  $credential
     * @param  array<string, mixed>  $data
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     *
     * @throws \Throwable
     */
    private function request(string $uri, string $credential, array $data = []): TestResponse
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $auth->forgetGuardState();

        return $this->withToken($credential)->postJson($uri, $data);
    }
}
