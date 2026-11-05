<?php

declare(strict_types = 1);

namespace Tests\Feature\Storage;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Orchestra\Testbench\Foundation\Env;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException;
use SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Storage\ConnectionAlignment;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Fixtures\Storage\PublishesSsoConfigurationWithoutStorage;
use Tests\Fixtures\Storage\RecordsMemberConnections;
use Tests\TestCase;

/**
 * Feature tests for keeping every member's storage connection on the one this
 * package configures (IAM-2.3): unset member keys are given it as this package
 * registers, a member key naming the same connection boots, and one naming
 * another refuses boot, whatever order the providers register in.
 *
 * With `iam.storage.connection` unset, the shared connection is the default
 * one: nothing is written, and only a member key naming a connection other than
 * the default refuses boot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionAlignment::class)]
final class ConnectionAlignmentTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var string A connection no key in these tests is aligned to. */
    private const string ELSEWHERE = 'elsewhere';

    /** @var array<string, class-string<\Illuminate\Support\ServiceProvider>> Each aligned member's configuration root and the provider that merges it. */
    private const array MEMBERS = [
        'authentication' => AuthenticationServiceProvider::class,
        'mfa'            => MfaServiceProvider::class,
        'sso'            => SsoServiceProvider::class,
    ];

    /** @var list<string> The environment variables this test set, cleared once its application is destroyed. */
    private array $environment = [];

    /**
     * Destroy the application, then clear the environment variables the test
     * set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        foreach ($this->environment as $name) {
            Env::forget($name);
        }
    }

    /**
     * Every unset member key, `null` or empty, is given the shared connection,
     * and nothing else in the member's configuration changes.
     *
     * @return void
     */
    public function testAlignWritesTheSharedConnectionIntoEveryUnsetMemberKey(): void
    {
        $config = self::configured('pgsql', [null, '', null]);

        $config->set('mfa.storage.retained', 'kept');
        $config->set('sso.endpoints', ['base_url' => 'https://sso.test']);

        (new ConnectionAlignment)->align($config);

        self::assertSame(['pgsql', 'pgsql', 'pgsql'], self::memberConnections($config));
        self::assertSame('kept', $config->get('mfa.storage.retained'));
        self::assertSame(['base_url' => 'https://sso.test'], $config->get('sso.endpoints'));
    }

    /**
     * A member key that names a connection is left as it is, whether or not it
     * is the shared one; `assertAligned()` judges it.
     *
     * @return void
     */
    public function testAlignLeavesAMemberKeyThatNamesAConnection(): void
    {
        $config = self::configured('pgsql', ['pgsql', 'mysql', null]);

        (new ConnectionAlignment)->align($config);

        self::assertSame(['pgsql', 'mysql', 'pgsql'], self::memberConnections($config));
    }

    /**
     * A member whose configuration is not merged yet is left alone, so the
     * value it merges from its own environment later is never masked.
     *
     * @return void
     */
    public function testAlignLeavesAMemberWhoseConfigurationIsNotMerged(): void
    {
        $config = self::configured('pgsql', [null, null, null], 'mysql', 'mfa');

        (new ConnectionAlignment)->align($config);

        self::assertFalse($config->has('mfa'));
        self::assertSame('pgsql', $config->get('authentication.storage.connection'));
        self::assertSame('pgsql', $config->get('sso.storage.connection'));
    }

    /**
     * A merged member whose configuration has no storage key yet is given one,
     * beside what it has.
     *
     * @return void
     */
    public function testAlignWritesTheKeyIntoAMergedMemberThatLacksIt(): void
    {
        $config = new Repository([
            'iam' => ['storage' => ['connection' => 'pgsql']],
            'sso' => ['endpoints' => ['base_url' => 'https://sso.test']],
        ]);

        (new ConnectionAlignment)->align($config);

        self::assertSame(['endpoints' => ['base_url' => 'https://sso.test'], 'storage' => ['connection' => 'pgsql']], $config->get('sso'));
        self::assertFalse($config->has('authentication'));
    }

    /**
     * What a call writes is returned, keyed by the member key, and nothing it
     * leaves is.
     *
     * @return void
     */
    public function testAlignReturnsWhatItWrote(): void
    {
        $config = self::configured('pgsql', [null, 'mysql', '']);

        self::assertSame(['authentication.storage.connection' => 'pgsql', 'sso.storage.connection' => 'pgsql'], (new ConnectionAlignment)->align($config));
        self::assertSame([], (new ConnectionAlignment)->align($config));
    }

    /**
     * A key an earlier call wrote, and that still holds what it wrote, follows
     * the shared connection once that changes, back to unset when it is unset;
     * a key the application changed since is its own, and is left.
     *
     * @return void
     */
    public function testAKeyAnEarlierCallWroteFollowsTheSharedConnection(): void
    {
        $config  = self::configured('pgsql', [null, null, null]);
        $written = (new ConnectionAlignment)->align($config);

        $config->set('sso.storage.connection', 'mysql');
        $config->set(StorageConnection::KEY, 'sqlite');

        self::assertSame(['authentication.storage.connection' => 'sqlite', 'mfa.storage.connection' => 'sqlite'], (new ConnectionAlignment)->align($config, $written));
        self::assertSame(['sqlite', 'sqlite', 'mysql'], self::memberConnections($config));

        $config->set(StorageConnection::KEY, null);

        (new ConnectionAlignment)->align($config, ['authentication.storage.connection' => 'sqlite', 'mfa.storage.connection' => 'pgsql']);

        self::assertSame([null, 'sqlite', 'mysql'], self::memberConnections($config));
    }

    /**
     * Given the application, a member whose service provider has not registered
     * yet is left alone even when its configuration is present, as an
     * application's published configuration is before any provider registers; a
     * member whose provider has registered is aligned.
     *
     * @return void
     */
    public function testAlignLeavesAMemberWhoseProviderHasNotRegistered(): void
    {
        $config = self::configured('pgsql', [null, null, null]);
        $app    = \Mockery::mock(Application::class);

        foreach (self::MEMBERS as $root => $provider) {
            $app->shouldReceive('getProviders')->with($provider)->andReturn($root === 'mfa' ? [] : [new \stdClass]);
        }

        (new ConnectionAlignment)->align($config, [], $app);

        self::assertSame(['pgsql', null, 'pgsql'], self::memberConnections($config));
    }

    /**
     * Rows of `[shared]`: a shared connection that means the default one.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideUnsetSharedConnections(): iterable
    {
        yield 'null' => [null];
        yield 'empty' => [''];
    }

    /**
     * With no shared connection, the members' unset keys already mean the
     * default connection, so nothing is written: an empty key stays empty.
     *
     * @param  ?string  $shared
     * @return void
     */
    #[DataProvider('provideUnsetSharedConnections')]
    public function testWithNoSharedConnectionAlignWritesNothing(?string $shared): void
    {
        $config = self::configured($shared, [null, '', 'mysql']);
        $before = $config->all();

        (new ConnectionAlignment)->align($config);

        self::assertSame($before, $config->all());
    }

    /**
     * A member key that is neither a name, `null` nor empty fails closed rather
     * than being overwritten.
     *
     * @return void
     */
    public function testAlignRefusesAMalformedMemberKey(): void
    {
        $config = self::configured('pgsql', [null, null, null]);

        $config->set('mfa.storage.connection', 3);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`mfa.storage.connection` must be a connection name');

        (new ConnectionAlignment)->align($config);
    }

    /**
     * A malformed shared connection fails closed.
     *
     * @return void
     */
    public function testAlignRefusesAMalformedSharedConnection(): void
    {
        $config = self::configured(null, [null, null, null]);

        $config->set(StorageConnection::KEY, ['pgsql']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`iam.storage.connection` must be a connection name');

        (new ConnectionAlignment)->align($config);
    }

    /**
     * Rows of `[shared, members, default]`: a shared connection, the three
     * member keys' values in order, and the default connection, all of which
     * agree.
     *
     * @return iterable<string, array{0: ?string, 1: list<?string>, 2: string}>
     */
    public static function provideAlignedConnections(): iterable
    {
        yield 'every key naming the shared connection' => ['pgsql', ['pgsql', 'pgsql', 'pgsql'], 'mysql'];
        yield 'nothing set' => [null, [null, null, null], 'mysql'];
        yield 'members naming the default with no shared connection' => [null, ['mysql', '', null], 'mysql'];
        yield 'the shared connection naming the default with members unset' => ['mysql', [null, '', null], 'mysql'];
        yield 'an empty shared connection with a member naming the default' => ['', [null, 'mysql', null], 'mysql'];
    }

    /**
     * Keys that resolve to the same connection agree, an unset or empty one
     * resolving to the default, and checking them changes nothing.
     *
     * @param  ?string  $shared
     * @param  list<?string>  $members
     * @param  string  $default
     * @return void
     */
    #[DataProvider('provideAlignedConnections')]
    public function testAssertAlignedAcceptsKeysNamingOneConnection(?string $shared, array $members, string $default): void
    {
        $config = self::configured($shared, $members, $default);
        $before = $config->all();

        (new ConnectionAlignment)->assertAligned($config);

        self::assertSame($before, $config->all());
    }

    /**
     * Rows of `[shared, members, default, key, member]`: a shared connection,
     * the three member keys' values in order and the default connection, which
     * disagree, then the first member key that differs and what it names.
     *
     * @return iterable<string, array{0: ?string, 1: list<?string>, 2: string, 3: string, 4: ?string}>
     */
    public static function provideMisalignedConnections(): iterable
    {
        yield 'a member naming another connection' => ['pgsql', ['pgsql', 'mysql', 'pgsql'], 'pgsql', 'mfa.storage.connection', 'mysql'];
        yield 'a member naming another with no shared connection' => [null, [null, '', 'mysql'], 'pgsql', 'sso.storage.connection', 'mysql'];
        yield 'an unset member against a shared connection off the default' => ['pgsql', [null, 'pgsql', 'pgsql'], 'mysql', 'authentication.storage.connection', null];
        yield 'the first of several differing members' => ['pgsql', ['mysql', 'sqlite', 'pgsql'], 'pgsql', 'authentication.storage.connection', 'mysql'];
    }

    /**
     * A member key resolving to another connection than the shared one is
     * refused, naming the first such key, what it names, and the shared
     * connection as configured.
     *
     * @param  ?string  $shared
     * @param  list<?string>  $members
     * @param  string  $default
     * @param  string  $key
     * @param  ?string  $member
     * @return void
     */
    #[DataProvider('provideMisalignedConnections')]
    public function testAssertAlignedRefusesAMemberKeyNamingAnotherConnection(?string $shared, array $members, string $default, string $key, ?string $member): void
    {
        $config = self::configured($shared, $members, $default);

        try {
            (new ConnectionAlignment)->assertAligned($config);
        } catch (StorageConnectionMismatchException $exception) {
            self::assertSame($key, $exception->key);
            self::assertSame($member, $exception->member);
            self::assertSame($shared === '' ? null : $shared, $exception->storage);

            return;
        }

        self::fail('A member key naming another connection was accepted.');
    }

    /**
     * A member whose configuration is not merged has nothing to check.
     *
     * @return void
     */
    public function testAssertAlignedSkipsAMemberWhoseConfigurationIsNotMerged(): void
    {
        $config = self::configured('pgsql', ['pgsql', null, 'pgsql'], 'mysql', 'mfa');

        (new ConnectionAlignment)->assertAligned($config);

        self::assertFalse($config->has('mfa'));
    }

    /**
     * The members after one whose configuration is not merged are still
     * checked.
     *
     * @return void
     */
    public function testAssertAlignedChecksTheMembersAfterAnUnmergedOne(): void
    {
        $config = self::configured('pgsql', ['pgsql', null, 'mysql'], 'mysql', 'mfa');

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('sso.storage.connection names [mysql]');

        (new ConnectionAlignment)->assertAligned($config);
    }

    /**
     * Given the application, a member whose service provider has not registered
     * yet is not checked, even when its configuration is present; the members
     * whose providers have registered still are.
     *
     * @return void
     */
    public function testAssertAlignedSkipsAMemberWhoseProviderHasNotRegistered(): void
    {
        $config = self::configured('pgsql', ['pgsql', null, 'pgsql']);

        (new ConnectionAlignment)->assertAligned($config, self::applicationWithout('mfa'));

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('mfa.storage.connection names [default]');

        (new ConnectionAlignment)->assertAligned($config, self::applicationWithout());
    }

    /**
     * Given the application, the members after one whose provider has not
     * registered are still checked.
     *
     * @return void
     */
    public function testAssertAlignedChecksTheMembersAfterAnUnregisteredOne(): void
    {
        $config = self::configured('pgsql', ['pgsql', null, 'mysql']);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('sso.storage.connection names [mysql]');

        (new ConnectionAlignment)->assertAligned($config, self::applicationWithout('mfa'));
    }

    /**
     * Rows of `[root, provider]`: each member whose storage is aligned, and its
     * service provider.
     *
     * @return iterable<string, array{0: string, 1: class-string<\Illuminate\Support\ServiceProvider>}>
     */
    public static function provideMembers(): iterable
    {
        foreach (self::MEMBERS as $root => $provider) {
            yield $root => [$root, $provider];
        }
    }

    /**
     * A member whose service provider has not registered is refused, naming the
     * provider and the member's key.
     *
     * @param  string  $root
     * @param  class-string<\Illuminate\Support\ServiceProvider>  $provider
     * @return void
     */
    #[DataProvider('provideMembers')]
    public function testAssertRegisteredRefusesAMemberWhoseProviderHasNotRegistered(string $root, string $provider): void
    {
        try {
            (new ConnectionAlignment)->assertRegistered(self::applicationWithout($root));
        } catch (MemberNotRegisteredException $exception) {
            self::assertSame($root . '.storage.connection', $exception->key);
            self::assertSame($provider, $exception->provider);

            return;
        }

        self::fail('A member whose provider has not registered was accepted.');
    }

    /**
     * Every member's service provider registered, nothing is refused.
     *
     * @return void
     */
    public function testAssertRegisteredAcceptsEveryMemberRegistered(): void
    {
        $this->expectNotToPerformAssertions();

        (new ConnectionAlignment)->assertRegistered(self::applicationWithout());
    }

    /**
     * A malformed member key fails closed rather than counting as the default
     * connection.
     *
     * @return void
     */
    public function testAssertAlignedRefusesAMalformedMemberKey(): void
    {
        $config = self::configured(null, [null, null, null]);

        $config->set('sso.storage.connection', false);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`sso.storage.connection` must be a connection name');

        (new ConnectionAlignment)->assertAligned($config);
    }

    /**
     * Booted in any provider order, every member key the application leaves
     * unset names the shared connection, and the rest of each member's
     * configuration is the member's own.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    public function testUnsetMemberKeysReceiveTheSharedConnectionInAnyOrder(array $providers): void
    {
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION]);

        $this->bootInOrder($providers);

        $config = $this->config();

        self::assertSame([self::CONNECTION, self::CONNECTION, self::CONNECTION], self::memberConnections($config));

        foreach (self::MEMBERS as $root => $provider) {
            self::assertSame(array_keys(self::packageConfiguration($provider, $root)), array_keys((array) $config->get($root)), $root);
        }
    }

    /**
     * The shared connection is written as this package registers, so a provider
     * registering after it, before anything boots, already reads it.
     *
     * @return void
     */
    public function testTheSharedConnectionIsWrittenAtRegister(): void
    {
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION]);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, RecordsMemberConnections::class]);

        self::assertSame(
            array_fill_keys(StorageConnection::MEMBER_KEYS, self::CONNECTION),
            $this->app?->make(RecordsMemberConnections::RECORDED),
        );
    }

    /**
     * A member key the application set to the shared connection boots in any
     * provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    public function testAMemberKeyNamingTheSharedConnectionBoots(array $providers): void
    {
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'MFA_STORAGE_CONNECTION' => self::CONNECTION]);

        $this->bootInOrder($providers);

        self::assertTrue($this->app?->isBooted());
        self::assertSame([self::CONNECTION, self::CONNECTION, self::CONNECTION], self::memberConnections($this->config()));
    }

    /**
     * A member key the application set to another connection refuses boot in
     * any provider order, even where the member merges its configuration after
     * this package registers.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    public function testAMemberKeyNamingAnotherConnectionRefusesBoot(array $providers): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'SSO_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('sso.storage.connection names [elsewhere], but iam.storage.connection names [testing]');

        $this->bootInOrder($providers);
    }

    /**
     * An application whose published SSO configuration lacks the `storage`
     * block keeps SSO's own connection from its environment, which then refuses
     * boot, in any provider order: this package writes nothing into the
     * published configuration before SSO has merged its own over it.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    public function testAPublishedConfigurationWithoutStorageKeepsTheMembersOwnConnection(array $providers): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'SSO_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('sso.storage.connection names [elsewhere], but iam.storage.connection names [testing]');

        $this->bootInOrder([PublishesSsoConfigurationWithoutStorage::class, ...$providers]);
    }

    /**
     * With no shared connection, every member key the application leaves unset
     * stays unset, meaning the default connection, in any provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    public function testWithNoSharedConnectionMemberKeysStayUnset(array $providers): void
    {
        $this->bootInOrder($providers);

        self::assertSame([null, null, null], self::memberConnections($this->config()));
    }

    /**
     * With no shared connection, a member key naming a connection other than
     * the default refuses boot, naming the default as the shared connection.
     *
     * @return void
     */
    public function testWithNoSharedConnectionAMemberKeyOffTheDefaultRefusesBoot(): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->withEnvironment(['MFA_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('mfa.storage.connection names [elsewhere], but iam.storage.connection names [default]');

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class]);
    }

    /**
     * Build a configuration with the given shared connection, member key values
     * in `MEMBER_KEYS` order, and default connection, and with every aligned
     * member merged except the one named as unmerged.
     *
     * @param  ?string  $shared
     * @param  list<?string>  $members
     * @param  string  $default
     * @param  ?string  $unmerged
     * @return \Illuminate\Config\Repository
     */
    private static function configured(?string $shared, array $members, string $default = 'mysql', ?string $unmerged = null): Repository
    {
        $config = new Repository([
            'database' => ['default' => $default],
            'iam'      => ['storage' => ['connection' => $shared]],
        ]);

        foreach (StorageConnection::MEMBER_KEYS as $index => $key) {

            if (str_starts_with($key, $unmerged . '.')) {
                continue;
            }

            $config->set($key, $members[$index]);
        }

        return $config;
    }

    /**
     * Return an application on which every member's service provider has
     * registered but the given member's.
     *
     * @param  ?string  $missing
     * @return \Illuminate\Contracts\Foundation\Application
     */
    private static function applicationWithout(?string $missing = null): Application
    {
        $app = \Mockery::mock(Application::class);

        foreach (self::MEMBERS as $root => $provider) {
            $app->shouldReceive('getProviders')->with($provider)->andReturn($root === $missing ? [] : [new \stdClass]);
        }

        return $app;
    }

    /**
     * Return the member keys' values, in `MEMBER_KEYS` order.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<mixed>
     */
    private static function memberConnections(Repository $config): array
    {
        return array_map(static fn (string $key): mixed => $config->get($key), StorageConnection::MEMBER_KEYS);
    }

    /**
     * Return a member's packaged configuration, as its provider merges it.
     *
     * @param  class-string<\Illuminate\Support\ServiceProvider>  $provider
     * @param  string  $root
     * @return array<string, mixed>
     */
    private static function packageConfiguration(string $provider, string $root): array
    {
        $directory = dirname((string) (new \ReflectionClass($provider))->getFileName(), 2);

        /** @var array<string, mixed> */
        return require $directory . '/config/' . $root . '.php';
    }

    /**
     * Set environment variables for the next application, to be cleared once
     * the test ends.
     *
     * @param  array<string, string>  $variables
     * @return void
     */
    private function withEnvironment(array $variables): void
    {
        foreach ($variables as $name => $value) {
            Env::set($name, $value);

            $this->environment[] = $name;
        }
    }

    /**
     * Return the booted application's configuration.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): Repository
    {
        $config = $this->app?->make('config');

        self::assertInstanceOf(Repository::class, $config);

        return $config;
    }
}
