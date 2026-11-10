<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\Member;
use Tests\TestCase;

/**
 * Integration tests for the subject resolver's lifetime as
 * `laravel-authorization`'s resolution memo reads it (IAM-6.1, IAM-8.1): one
 * resolver for a request or job, as `laravel-authorization`'s own scoped
 * default is, so the tenant it resolved for the request is kept while the
 * resolver that resolved it is the one bound, and checks after the first in one
 * request are answered from the memo, reading nothing again.
 *
 * The checks run on every engine, and at READ COMMITTED and REPEATABLE READ on
 * MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationSeams::class)]
#[CoversClass(SubjectResolverAdapter::class)]
final class SubjectResolutionMemoTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /** @var string The action a refund is. */
    private const string REFUND = 'invoices:refund';

    /** @var int How many checks are asked again once the first is answered. */
    private const int REPEATS = 3;

    /**
     * Checks asked again in one request keep the tenant resolved for it, and
     * read nothing from the database, the first check's resolution answering
     * them.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testChecksAskedAgainInOneRequestAreAnsweredFromTheMemo(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $token = $this->signIn($this->member());

        $this->withToken($token)->getJson('/repeat')
            ->assertOk()
            ->assertExactJson(['allowed' => true, 'queries' => 0, 'tenant_kept' => true, 'resolver_kept' => true]);
    }

    /**
     * Define the route that checks once, then again, counting what the repeat
     * checks read and whether the tenant resolved for the request is kept.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->get('repeat', static function (Application $app): JsonResponse {

            $allowed  = Authorization::can(self::REFUND);
            $tenant   = $app->make(ResolvedTenant::class);
            $resolver = $app->make(SubjectResolver::class);

            DB::flushQueryLog();
            DB::enableQueryLog();

            for ($check = 0; $check < self::REPEATS; $check++) {
                $allowed = Authorization::can(self::REFUND) && $allowed;
            }

            TenantScope::scopeKey();
            TenantScope::currentChain();

            $queries = count(DB::getQueryLog());

            DB::disableQueryLog();

            return new JsonResponse([
                'allowed'       => $allowed,
                'queries'       => $queries,
                'tenant_kept'   => $app->make(ResolvedTenant::class)  === $tenant,
                'resolver_kept' => $app->make(SubjectResolver::class) === $resolver,
            ]);
        })->middleware('auth:' . self::GUARD);
    }

    /**
     * Load the application's configuration, then sign members in on the guard
     * people sign in on, and declare the invoice permissions, set before any
     * provider registers.
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
     * A member whose only grant is a policy allowing a refund.
     *
     * @return \Tests\Fixtures\Authorization\Member
     */
    private function member(): Member
    {
        $member = Member::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test', 'password' => self::PASSWORD]);

        $member->attachPolicy(Policy::query()->create([
            'name'     => 'refunds',
            'document' => ['statements' => [['sid' => 'refund', 'effect' => 'allow', 'actions' => [self::REFUND]]]],
        ]));

        return $member;
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
}
