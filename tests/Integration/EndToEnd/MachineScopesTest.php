<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Iam\Authorization\ScopeRegistryAdapter;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\Enums\ReportPermission;
use Tests\Fixtures\Authorization\ServiceAccount;
use Tests\Fixtures\Authorization\UnmarkedServiceAccount;
use Tests\TestCase;

/**
 * End-to-end tests of a machine caller's scopes bounding its policy (IAM-6.5),
 * with every adapter of this package's bound: a service account granted every
 * report permission, calling with an API key `laravel-authentication` issued,
 * is allowed only what the key's scopes cover, through
 * `laravel-authorization`'s manager and Laravel's Gate alike; a key with no
 * scopes allows nothing; a scope the scope map names covers what it stands for,
 * yet grants nothing the account does not hold; another account named by the
 * caller is no credential's, so a machine is allowed nothing, one the
 * application has not marked as `laravel-authorization`'s machine among them;
 * and a key is never issued a scope naming no permission.
 *
 * The keys are authenticated on a route served by the `api_key` guard, as an
 * application serves its machine callers. Everything runs on every engine, and
 * at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionPolicySourceAdapter::class)]
#[CoversClass(ScopeRegistryAdapter::class)]
final class MachineScopesTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /** @var string The guard service accounts authenticate on with an API key. */
    private const string KEYS = 'keys';

    /** @var string The route a machine caller asks what it may do on. */
    private const string ROUTE = '/reports';

    /** @var list<string> Every report permission, each granted to the account. */
    private const array REPORTS = ['reports:read', 'reports:export', 'reports:delete'];

    /**
     * Declare the guard service accounts authenticate on, the permissions they
     * are granted, and the route a machine caller asks on.
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

        foreach (self::REPORTS as $permission) {
            Permission::query()->create(['name' => $permission]);
        }

        Route::middleware('auth:' . self::KEYS)->get(self::ROUTE, static function (): array {

            $other = ServiceAccount::query()->where('name', 'Billing')->firstOrFail();

            return [
                'manager' => array_combine(self::REPORTS, array_map(static fn (string $action): bool => Authorization::can($action), self::REPORTS)),
                'gate'    => array_combine(self::REPORTS, array_map(static fn (string $action): bool => Gate::allows($action), self::REPORTS)),
                'other'   => Authorization::for($other)->can('reports:read'),
            ];
        });
    }

    /**
     * Rows of `[isolation level, scopes the key is issued, the report
     * permissions they allow]`.
     *
     * @return iterable<string, array{0: ?string, 1: list<string>, 2: list<string>}>
     */
    public static function provideKeys(): iterable
    {
        foreach (self::provideEveryIsolationLevel() as $name => [$level]) {

            yield $name . ', a key for reading' => [$level, ['reports:read'], ['reports:read']];

            yield $name . ', a key for reading and exporting' => [$level, ['reports:read', 'reports:export'], ['reports:read', 'reports:export']];

            yield $name . ', a key covering every report' => [$level, ['reports:*'], self::REPORTS];

            yield $name . ', a key with no scopes' => [$level, [], []];
        }
    }

    /**
     * A service account granted every report permission is allowed only what
     * its key's scopes cover, through the manager and the Gate alike, and
     * another account the caller names is allowed nothing.
     *
     * @param  ?string  $level
     * @param  list<string>  $scopes
     * @param  list<string>  $allowed
     * @return void
     */
    #[DataProvider('provideKeys')]
    public function testAKeysScopesBoundWhatItsAccountMayDo(?string $level, array $scopes, array $allowed): void
    {
        self::runAtIsolationLevel($level);

        $key = $this->issueKey($this->grantedAccount('Reporting'), $scopes);

        $this->grantedAccount('Billing');

        $expected = array_combine(self::REPORTS, array_map(static fn (string $action): bool => in_array($action, $allowed, true), self::REPORTS));

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])
            ->assertOk()
            ->assertExactJson(['manager' => $expected, 'gate' => $expected, 'other' => false]);
    }

    /**
     * A scope the scope map names covers the actions it stands for, yet grants
     * nothing the account does not hold.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMappedScopeCoversWhatItStandsForAndGrantsNothing(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $account = ServiceAccount::query()->create(['name' => 'Reporting']);

        $account->givePermission('reports:read');

        $key = $this->issueKey($account, ['reporting']);

        $this->grantedAccount('Billing');

        $this->getJson(self::ROUTE, ['Authorization' => 'Bearer ' . $key])
            ->assertOk()
            ->assertJsonPath('manager', ['reports:read' => true, 'reports:export' => false, 'reports:delete' => false]);
    }

    /**
     * A machine the application has not marked as `laravel-authorization`'s
     * (`AuthorizableMachine`), granted every report permission, is allowed
     * nothing wherever no credential of its own caps it: named by a caller on
     * another account's key, and through the manager or the Gate outside any
     * request.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMachineWithoutAuthorizationsMarkerIsAllowedNothingWhereNoCredentialCapsIt(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $unmarked = UnmarkedServiceAccount::query()->create(['name' => 'Unmarked']);

        foreach (self::REPORTS as $permission) {
            $unmarked->givePermission($permission);
        }

        $key = $this->issueKey($this->grantedAccount('Reporting'), ['reports:*']);

        Route::middleware('auth:' . self::KEYS)->get('/unmarked', static fn (): array => [
            'named' => Authorization::for(UnmarkedServiceAccount::query()->findOrFail($unmarked->id))->can('reports:read'),
        ]);

        $this->getJson('/unmarked', ['Authorization' => 'Bearer ' . $key])->assertOk()->assertExactJson(['named' => false]);

        self::assertFalse(Authorization::for($unmarked)->can('reports:read'));
        self::assertFalse(Gate::forUser($unmarked)->allows('reports:read'));
    }

    /**
     * A key is never issued a scope naming no permission.
     *
     * @return void
     */
    public function testAKeyIsNeverIssuedAScopeNamingNoPermission(): void
    {
        $this->expectException(InvalidScopeException::class);

        $this->issueKey($this->grantedAccount('Reporting'), ['reports:read', 'payroll:read']);
    }

    /**
     * Load the application's configuration, then declare the report permissions
     * and the scope map before any provider registers, the session block set as
     * a whole, as a published file holds it.
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
     * Create a service account granted every report permission.
     *
     * @param  string  $name
     * @return \Tests\Fixtures\Authorization\ServiceAccount
     */
    private function grantedAccount(string $name): ServiceAccount
    {
        $account = ServiceAccount::query()->create(['name' => $name]);

        foreach (self::REPORTS as $permission) {
            $account->givePermission($permission);
        }

        return $account;
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
