<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Enums\ReportPermission;
use Tests\Fixtures\Authorization\RecordingSessionPolicySource;
use Tests\Fixtures\Authorization\ServiceAccount;
use Tests\Fixtures\Authorization\Staff;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authorization`'s session policy source
 * answered from the scopes of the caller's credential (IAM-6.5, AUTH-4.5),
 * which the subject resolver puts on the subject: a check about a service
 * account calling with an API key is capped by the scopes the key was issued,
 * an empty list included, and one about a person signed in to a session is
 * capped by nothing. A subject the caller names for another model carries no
 * scopes, so a person named is capped by nothing and a machine named is allowed
 * nothing, whatever the caller's own credential carries; outside a request
 * there is no credential, and a machine is allowed nothing.
 *
 * The credentials are real ones: an API key `laravel-authentication` issues and
 * authenticates, and a session a person signs in to with a password, and each
 * check is asked through `laravel-authorization`'s facade, whose source records
 * what it answered. The source reads nothing but the subject, so no read mode
 * applies to it; it is run on every engine at the connection's own level.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionPolicySourceAdapter::class)]
#[CoversClass(SubjectResolverAdapter::class)]
final class SessionPolicySourceAdapterTest extends TestCase
{
    use MigratesAuthorization, SignsInPeople;

    /** @var string The guard service accounts authenticate on with an API key. */
    private const string KEYS = 'keys';

    /** @var string The route a test asks its checks on. */
    private const string ROUTE = '/scopes';

    /** @var \Tests\Fixtures\Authorization\RecordingSessionPolicySource The bound source, recording what the adapter answers. */
    private RecordingSessionPolicySource $source;

    /**
     * Declare the guard service accounts authenticate on and the permission
     * they are granted, and bind the source, recording its answers, as an
     * application would bind it.
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

        Permission::query()->create(['name' => 'reports:read']);

        $this->source = new RecordingSessionPolicySource(new SessionPolicySourceAdapter);

        $this->app?->instance(SessionPolicySource::class, $this->source);
    }

    /**
     * Rows of `[the scopes the key is issued]`.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideIssuedScopes(): iterable
    {
        yield 'two scopes' => [['reports:read', 'reports:export']];

        yield 'none' => [[]];
    }

    /**
     * A check about a service account calling with an API key reaches the
     * source with the scopes the key was issued, carried on the request's
     * subject, and is capped by them: an empty list allows nothing the account
     * is granted.
     *
     * @param  list<string>  $scopes
     * @return void
     */
    #[DataProvider('provideIssuedScopes')]
    public function testAnApiKeysScopesReachTheSource(array $scopes): void
    {
        $account = $this->createAccount();

        $account->givePermission('reports:read');

        $key = $this->issueKey($account, $scopes);

        $this->askOn(self::KEYS, static fn (): array => [
            'subject' => Authorization::currentSubject()?->scopes,
            'allowed' => Authorization::can('reports:read'),
        ]);

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])
            ->assertOk()
            ->assertExactJson(['subject' => $scopes, 'allowed' => in_array('reports:read', $scopes, true), 'answers' => [$scopes]]);
    }

    /**
     * A check about a person signed in to a session reaches the source with no
     * scopes, so it is capped by nothing.
     *
     * @return void
     */
    public function testAPersonsSessionReachesTheSourceWithNoCap(): void
    {
        $token = $this->signIn($this->createPerson())->tokens->accessToken->reveal();

        $this->askOn(self::GUARD, static fn (): array => [
            'subject' => Authorization::currentSubject()?->scopes,
            'allowed' => Authorization::can('reports:read'),
        ]);

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $token])
            ->assertOk()
            ->assertExactJson(['subject' => null, 'allowed' => false, 'answers' => [null]]);
    }

    /**
     * A subject the caller names for another model carries none of the caller's
     * scopes: a person named reaches the source with no cap, and a machine
     * named is allowed nothing, whatever the caller's key carries.
     *
     * @return void
     */
    public function testASubjectNamedForAnotherModelCarriesNoScopes(): void
    {
        $key    = $this->issueKey($this->createAccount(), ['reports:read']);
        $person = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);
        $other  = $this->createAccount('Billing');

        $this->askOn(self::KEYS, static fn (): array => [
            'subject' => Authorization::currentSubject()?->withSubject($person)->scopes,
            'allowed' => [Authorization::for($person)->can('reports:read'), Authorization::for($other)->can('reports:read')],
        ]);

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])
            ->assertOk()
            ->assertExactJson(['subject' => null, 'allowed' => [false, false], 'answers' => [null, []]]);
    }

    /**
     * Outside a request no credential is held, so a check about a service
     * account reaches the source with no scopes and is allowed nothing.
     *
     * @return void
     */
    public function testOutsideARequestAMachineIsAllowedNothing(): void
    {
        $account = $this->createAccount();

        $account->givePermission('reports:read');

        self::assertFalse(Authorization::for($account)->can('reports:read'));
        self::assertSame([[]], $this->source->answers);
    }

    /**
     * Load the application's configuration, then declare the report permissions
     * before any provider registers, so the scope registry lets a key carry
     * them.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $app->make('config')->set('authorization.permission_enums', [ReportPermission::class]);
    }

    /**
     * Serve the route, authenticated on the guard given, that asks the checks
     * the callback makes and answers what it returns, with what the source
     * answered while it asked them.
     *
     * @param  string  $guard
     * @param  \Closure(): array<string, mixed>  $checks
     * @return void
     */
    private function askOn(string $guard, \Closure $checks): void
    {
        Route::middleware('auth:' . $guard)->get(self::ROUTE, function () use ($checks): array {

            $this->source->answers = [];

            return [...$checks(), 'answers' => $this->source->answers];
        });
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

    /**
     * Issue the account an API key on the keys guard with the scopes given, and
     * answer the key it presents.
     *
     * @param  \Tests\Fixtures\Authorization\ServiceAccount  $account
     * @param  list<string>  $scopes
     * @return string
     */
    private function issueKey(ServiceAccount $account, array $scopes): string
    {
        return Auth::apiKeys(self::KEYS)->issue($account, $account, $scopes)->key()->reveal();
    }
}
