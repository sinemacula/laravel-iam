<?php

declare(strict_types = 1);

namespace Tests;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Concerns\MigratesAuditLog;
use Tests\Fixtures\Models\Person;

/**
 * Shared base test case for the package's feature and integration tests.
 *
 * Boots a minimal Testbench application with every member's service provider
 * registered, then this package's, and the database `DB_CONNECTION` names
 * (in-memory SQLite when unset), with a `jwt` guard people sign in on with a
 * password (`api`, the default guard, over the fixtures' `Person`) and the MFA
 * application of the same name, offering the factor types `mfaTypes()` names,
 * and a relying party for passkeys. Subclasses may override `mfaTypes()` and
 * `signInMethods()` to change what the application offers before any provider
 * registers (so the binding rule's switches read it), `defineEnvironment` to
 * add per-test config and `defineDatabaseMigrations` (or use `setUp`, or
 * `Concerns\MigratesMembers`) to create tables, and may boot the application
 * again with the providers in another order through `reorderProviders`.
 *
 * Every member's event is recorded in `laravel-audit-log` through this
 * package's mappers, so audit-log's fake store is bound for every test that
 * does not create audit-log's tables (`Concerns\MigratesAuditLog`): without
 * them, each record would fail to write, and be spilled and reported, on every
 * event of every flow. A test of the trail binds a fresh fake itself
 * (`AuditLog::fake()`) or creates the tables.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class TestCase extends OrchestraTestCase
{
    /** @var string The connection each test runs on, in its worker's database. */
    protected const string CONNECTION = 'testing';

    /** @var list<class-string<\Illuminate\Support\ServiceProvider>> Every member's service provider, in the order the tests register them by default. */
    protected const array MEMBER_PROVIDERS = [
        AuthenticationServiceProvider::class,
        AuthorizationServiceProvider::class,
        MfaServiceProvider::class,
        SsoServiceProvider::class,
        AuditLogServiceProvider::class,
    ];

    /** @var string The guard people sign in on, and the MFA application of the same name. */
    protected const string GUARD = 'api';

    /** @var string The relying party id passkeys are registered with. */
    protected const string RELYING_PARTY = 'iam.test';

    /** @var string The origin passkey ceremonies run on. */
    protected const string ORIGIN = 'https://app.iam.test';

    /** @var string The password every person the tests create signs in with. */
    protected const string PASSWORD = 'correct horse battery staple';

    /** @var list<string> The process's arguments while an Artisan command runs that the storage check does not stand aside for. */
    protected const array CHECKED_COMMAND = ['artisan', 'migrate'];

    /** @var string The database every worker database is named after. */
    private const string DATABASE = 'laravel_iam_test';

    /** @var array<string, true> Worker databases this process has created. */
    private static array $workerDatabases = [];

    /** @var ?list<class-string<\Illuminate\Support\ServiceProvider>> The providers in the order the test asked for; `null` for the members, then this package. */
    private ?array $providerOrder = null;

    /** @var ?list<string> The process's arguments before the test replaced them, restored once its application is destroyed. */
    private ?array $argv = null;

    /**
     * Boot the application, then bring the process's UUIDv7 generator back to
     * the present.
     *
     * The generator keeps one monotonic state for the whole process, and
     * audit-log names each record with a UUIDv7 of the time the record says it
     * occurred, which sets that state to that time, even an earlier one. A test
     * that moved the clock forward and recorded leaves the state ahead of the
     * clock, so the next test's ids would follow it, and the first record that
     * test writes would set it back, so two of `laravel-authentication`'s rows
     * of one second, whose order falls to their ids, would come in the wrong
     * order. A UUIDv7 made for the present starts each test from it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Str::uuid7(new \DateTimeImmutable);
    }

    /**
     * Destroy the application, then close its database connections and restore
     * the process's arguments.
     *
     * The application's objects reference each other, so a destroyed
     * application's PDO is only closed once the cycles are collected. Without
     * this, a long run against a persistent database holds dozens of
     * connections at once, and parallel workers exhaust the server's limit. The
     * connections are closed after every teardown callback, migration rollbacks
     * included, so none of them finds its connection gone.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        /** @var ?\Illuminate\Database\DatabaseManager $database */
        $database = $this->app?->make('db');

        parent::tearDown();

        foreach ($database?->getConnections() ?? [] as $connection) {
            $connection->disconnect();
        }

        gc_collect_cycles();

        if ($this->argv === null) {
            return;
        }

        $_SERVER['argv'] = $this->argv;
    }

    /**
     * Register every member's service provider, then this package's, unless the
     * test asked for another order.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return $this->providerOrder ?? [...self::MEMBER_PROVIDERS, IamServiceProvider::class];
    }

    /**
     * Destroy the application and boot a new one with the given providers
     * registered in the given order, as package discovery or an application's
     * own provider list might register them.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    protected function reorderProviders(array $providers): void
    {
        $this->providerOrder = $providers;

        $this->reloadApplication();
    }

    /**
     * Replace the process's arguments, as the console and this package's
     * storage check read them, until the test ends, so a test that expects the
     * check to refuse or to stand aside never depends on how the test runner
     * itself was invoked.
     *
     * @param  list<string>  $arguments
     * @return void
     */
    protected function withArguments(array $arguments): void
    {
        /** @var list<string> $argv */
        $argv = $_SERVER['argv'] ?? [];

        $this->argv ??= $argv;
        $_SERVER['argv'] = $arguments;
    }

    /**
     * Seed the database connection, and bind audit-log's fake store unless the
     * test creates audit-log's tables.
     *
     * Reads `DB_CONNECTION` from the environment to select the driver. Defaults
     * to in-memory SQLite when unset, so local development needs no extra
     * configuration.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('app.key', 'base64:' . base64_encode('laravel-iam test key!!!!!!!!!!!!'));
        $config->set('database.default', self::CONNECTION);
        $config->set('database.connections.' . self::CONNECTION, $this->databaseConnection());

        if (in_array(MigratesAuditLog::class, class_uses_recursive($this), true)) {
            return;
        }

        FakeAuditStore::fake($app);
    }

    /**
     * Load the application's configuration, then the guard and the MFA
     * application people sign in on, before any provider registers, as an
     * application's own configuration files would hold them.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $this->defineSignIn($app->make(ConfigRepository::class));
    }

    /**
     * The factor types the MFA application people sign in on offers: TOTP,
     * unless the test offers more. A test that offers `sms` or `email` binds a
     * sender or names a gateway for it before the application boots, since MFA
     * refuses to boot while one of them is offered with its own senders.
     *
     * @return list<string>
     */
    protected function mfaTypes(): array
    {
        return ['totp'];
    }

    /**
     * The sign-in methods the guard people sign in on allows: a password,
     * unless the test allows more (`passkey`, say).
     *
     * @return list<string>
     */
    protected function signInMethods(): array
    {
        return ['password'];
    }

    /**
     * Configure the guard people sign in on: a `jwt` guard of
     * `laravel-authentication`'s, the default, over the fixtures' people,
     * signing in with the methods `signInMethods()` names, with the relying
     * party passkeys are registered with, and the MFA application of the same
     * name, which offers the factor types `mfaTypes()` names to anyone who
     * enrols and declares the password its first factor. Hashing and the
     * credential timebox are cut to the least, so a sign-in costs a test next
     * to nothing.
     *
     * A member merges its packaged configuration one level deep beneath the
     * application's as it registers, so each member block set here is set
     * whole, the packaged values it does not change included, and reads the
     * same before the member registers and after.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    private function defineSignIn(ConfigRepository $config): void
    {
        $config->set('auth.defaults.guard', self::GUARD);
        $config->set('auth.guards.' . self::GUARD, [
            'driver'      => 'jwt',
            'provider'    => 'people',
            'application' => ['methods' => $this->signInMethods()],
        ]);
        $config->set('auth.providers.people', ['driver' => 'model', 'model' => Person::class]);
        $config->set('hashing.bcrypt.rounds', 4);

        $packaged = self::packagedConfiguration(AuthenticationServiceProvider::class, 'authentication');

        /** @var array<string, mixed> $jwt */
        $jwt = $packaged['jwt'];

        $config->set('authentication.jwt', [
            ...$jwt,
            'keys'     => ['default' => base64_encode('laravel-iam test signing key, 48 bytes long!!!!')],
            'issuer'   => 'https://iam.test',
            'audience' => 'https://iam.test/api',
        ]);
        $config->set('authentication.timebox', ['credentials_microseconds' => 1]);

        /** @var array<string, mixed> $passkeys */
        $passkeys = $packaged['passkeys'];

        $config->set('authentication.passkeys', [
            ...$passkeys,
            'relying_party' => ['id' => self::RELYING_PARTY, 'name' => 'IAM', 'origins' => [self::ORIGIN]],
        ]);

        $config->set('mfa.applications', [
            self::GUARD => [
                'types'        => $this->mfaTypes(),
                'requirement'  => 'enrolled',
                'first_factor' => ['method' => 'password', 'channel' => 'password'],
            ],
        ]);
    }

    /**
     * Return the configuration a member packages under the given key, read from
     * the file its provider merges.
     *
     * @param  class-string<\Illuminate\Support\ServiceProvider>  $provider
     * @param  string  $key
     * @return array<array-key, mixed>
     */
    private static function packagedConfiguration(string $provider, string $key): array
    {
        $file = (new \ReflectionClass($provider))->getFileName();

        assert(is_string($file));

        $configuration = require dirname($file, 2) . '/config/' . $key . '.php';

        assert(is_array($configuration));

        return $configuration;
    }

    /**
     * Build the database connection config from environment variables.
     *
     * @return array<string, ?string>
     */
    private function databaseConnection(): array
    {
        $driver = getenv('DB_CONNECTION') ?: 'sqlite';

        if ($driver === 'sqlite') {
            return [
                'driver'   => 'sqlite',
                'database' => ':memory:',
                'prefix'   => '',
            ];
        }

        $connection = [
            'driver'    => $driver,
            'host'      => getenv('DB_HOST') ?: '127.0.0.1',
            'port'      => getenv('DB_PORT') ?: $this->defaultPort($driver),
            'database'  => getenv('DB_DATABASE') ?: self::DATABASE,
            'username'  => getenv('DB_USERNAME') ?: $this->defaultUsername($driver),
            'password'  => getenv('DB_PASSWORD') ?: '',
            'prefix'    => '',
            'charset'   => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
            'collation' => $driver === 'pgsql' ? null : 'utf8mb4_unicode_ci',
        ];

        $connection['database'] = $this->workerDatabase($connection);

        return $connection;
    }

    /**
     * Return the database this process tests against.
     *
     * Tests create, empty and drop the same tables, so paratest workers sharing
     * one database would collide. Each process gets its own database, named
     * after its paratest `TEST_TOKEN` (`0` outside paratest) and created afresh
     * on first use from a connection to the configured one, so nothing a
     * previous or interrupted run left behind reaches the next, and the
     * configured database holds only what tests on Testbench's own connections
     * create.
     *
     * @param  array{driver: string, host: string, port: string, database: string, username: string, password: string}  $connection
     * @return string
     */
    private function workerDatabase(array $connection): string
    {
        $token    = getenv('TEST_TOKEN');
        $database = $connection['database'] . '_' . ($token === false || $token === '' ? '0' : $token);

        if (isset(self::$workerDatabases[$database])) {
            return $database;
        }

        $dsn = sprintf('%s:host=%s;port=%s;dbname=%s', $connection['driver'], $connection['host'], $connection['port'], $connection['database']);
        $pdo = new \PDO($dsn, $connection['username'], $connection['password']);

        $quoted = $connection['driver'] === 'pgsql' ? '"' . $database . '"' : '`' . $database . '`';

        $pdo->exec('DROP DATABASE IF EXISTS ' . $quoted . ($connection['driver'] === 'pgsql' ? ' WITH (FORCE)' : ''));
        $pdo->exec('CREATE DATABASE ' . $quoted);

        self::$workerDatabases[$database] = true;

        return $database;
    }

    /**
     * Return the default database port for the given driver.
     *
     * @param  string  $driver
     * @return string
     */
    private function defaultPort(string $driver): string
    {
        return $driver === 'pgsql' ? '5432' : '3306';
    }

    /**
     * Return the default database username for the given driver.
     *
     * @param  string  $driver
     * @return string
     */
    private function defaultUsername(string $driver): string
    {
        return $driver === 'pgsql' ? 'postgres' : 'root';
    }
}
