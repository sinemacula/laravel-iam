<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Application as FoundationApplication;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use Orchestra\Testbench\Foundation\Env;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException;
use SineMacula\Laravel\Iam\IamManager;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Iam\Workers\ResetBeforeJob;
use SineMacula\Laravel\Iam\Workers\ResetBetweenRequests;
use SineMacula\Laravel\Iam\Workers\ResetWhenWorkerStarts;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Fixtures\Providers\RecordsSettlementWhileBooting;
use Tests\Fixtures\Providers\RegistersIamWhileBooting;
use Tests\Fixtures\Storage\ChangesTheSharedConnection;
use Tests\Fixtures\Storage\RecordsMemberConnections;
use Tests\TestCase;

/**
 * Feature tests for the package service provider: the configuration and the
 * `iam` manager it registers, the storage connection it aligns as it registers
 * and again as the application boots, the binding rule's outcome it keeps, a
 * late registration settling at once, a registration while the application
 * boots settling from the provider's own `boot()`, the configuration commands a
 * mismatch does not refuse, the worker reset listeners and the publishing tag.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IamServiceProvider::class)]
final class IamServiceProviderTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var string A connection no key in these tests is aligned to. */
    private const string ELSEWHERE = 'elsewhere';

    /** @var list<string> The environment variables this test set, cleared once its application is destroyed. */
    private array $environment = [];

    /** @var ?list<string> The process's arguments before the test replaced them, restored once its application is destroyed. */
    private ?array $argv = null;

    /**
     * Destroy the application, then clear the environment variables the test
     * set and restore the process's arguments.
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

        if ($this->argv === null) {
            return;
        }

        $_SERVER['argv'] = $this->argv;
    }

    /**
     * The package's configuration is merged under `iam`, as the packaged file
     * declares it.
     *
     * @return void
     */
    public function testTheConfigurationIsMergedUnderIam(): void
    {
        self::assertSame(require self::configurationFile(), $this->config()->get('iam'));
    }

    /**
     * The manager is one shared instance, under `iam` and under its class name.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheManagerIsOneSharedInstanceUnderBothNames(): void
    {
        $app     = $this->application();
        $manager = $app->make('iam');

        self::assertInstanceOf(IamManager::class, $manager);
        self::assertSame($manager, $app->make('iam'));
        self::assertSame($manager, $app->make(IamManager::class));
    }

    /**
     * The shared connection is written into the member keys as this package
     * registers, so a provider registering straight after it already reads it.
     *
     * @return void
     */
    public function testTheSharedConnectionIsWrittenAsThePackageRegisters(): void
    {
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION]);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, RecordsMemberConnections::class]);

        self::assertSame(array_fill_keys(StorageConnection::MEMBER_KEYS, self::CONNECTION), $this->app?->make(RecordsMemberConnections::RECORDED));
    }

    /**
     * A member that registers after this package, and so merges its own
     * configuration only then, is aligned as the application boots, in every
     * provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    public function testEveryMemberIsAlignedOnceTheApplicationBoots(array $providers): void
    {
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION]);

        $this->bootInOrder($providers);

        $config = $this->config();

        self::assertSame(
            array_fill_keys(StorageConnection::MEMBER_KEYS, self::CONNECTION),
            array_combine(StorageConnection::MEMBER_KEYS, array_map(static fn (string $key): mixed => $config->get($key), StorageConnection::MEMBER_KEYS)),
        );
    }

    /**
     * A member key naming another connection refuses boot, in every provider
     * order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    public function testAMemberKeyNamingAnotherConnectionRefusesBoot(array $providers): void
    {
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'MFA_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('mfa.storage.connection names [elsewhere], but iam.storage.connection names [testing]');

        $this->bootInOrder($providers);
    }

    /**
     * A member key this package wrote as it registered follows the shared
     * connection when the application names another one in a later
     * `register()`, rather than being refused as the application's own.
     *
     * @return void
     */
    public function testAKeyThisPackageWroteFollowsASharedConnectionChangedLater(): void
    {
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, ChangesTheSharedConnection::class]);

        $config = $this->config();

        self::assertSame(ChangesTheSharedConnection::CONNECTION, $config->get(StorageConnection::KEY));

        foreach (StorageConnection::MEMBER_KEYS as $key) {
            self::assertSame(ChangesTheSharedConnection::CONNECTION, $config->get($key), $key . ' did not follow the shared connection.');
        }
    }

    /**
     * Rows of `[command]`: each console command that lists, describes,
     * discovers, caches or clears configuration.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUncheckedCommands(): iterable
    {
        foreach (['config:cache', 'config:clear', 'config:show', 'help', 'list', 'optimize:clear', 'package:discover'] as $command) {
            yield $command => [$command];
        }
    }

    /**
     * While a console command that lists, describes, discovers, caches or
     * clears configuration runs, a mismatch is not refused, so it can still be
     * inspected and cleared; the unset keys are still aligned and the binding
     * rule still applied.
     *
     * @param  string  $command
     * @return void
     */
    #[DataProvider('provideUncheckedCommands')]
    public function testAMismatchIsNotRefusedWhileAConfigurationCommandRuns(string $command): void
    {
        $this->withArguments(['artisan', '-v', $command]);
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'SSO_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class]);

        self::assertSame(self::ELSEWHERE, $this->config()->get('sso.storage.connection'));
        self::assertSame(self::CONNECTION, $this->config()->get('mfa.storage.connection'));
        self::assertTrue($this->application()->bound(BindingOutcome::class));
    }

    /**
     * Rows of `[variable, key]`: an environment variable that fills a
     * connection key this package reads, and that key.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideConnectionKeys(): iterable
    {
        yield 'the shared connection' => ['IAM_STORAGE_CONNECTION', StorageConnection::KEY];

        yield 'a member connection' => ['MFA_STORAGE_CONNECTION', 'mfa.storage.connection'];
    }

    /**
     * While a console command that clears or caches configuration runs, a
     * connection key that is not a name, a cached one included, does not stop
     * the application booting, so the command can still clear or replace it;
     * the key is left as it is.
     *
     * @param  string  $variable
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideConnectionKeys')]
    public function testAConnectionKeyThatIsNotANameIsNotRefusedWhileAConfigurationCommandRuns(string $variable, string $key): void
    {
        $this->withArguments(['artisan', 'config:clear']);
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, $variable => 'false']);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class]);

        self::assertFalse($this->config()->get($key));
        self::assertTrue($this->application()->isBooted());
        self::assertTrue($this->application()->bound(BindingOutcome::class));
    }

    /**
     * Any other console command, as the application's requests and jobs,
     * refuses a connection key that is not a name.
     *
     * @param  string  $variable
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideConnectionKeys')]
    public function testAConnectionKeyThatIsNotANameRefusesBootWhileAnotherCommandRuns(string $variable, string $key): void
    {
        $this->withArguments(['artisan', 'migrate']);
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, $variable => 'false']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`' . $key . '` must be a connection name');

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class]);
    }

    /**
     * Rows of `[key]`: the shared connection key and a member's.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideConnectionKeyNames(): iterable
    {
        foreach (self::provideConnectionKeys() as $label => [, $key]) {
            yield $label => [$key];
        }
    }

    /**
     * A connection key that is not a name is refused as the package registers,
     * not only once every provider has: an application provider that sets the
     * key later does not let it pass.
     *
     * @param  string  $key
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideConnectionKeyNames')]
    public function testAConnectionKeyThatIsNotANameIsRefusedAsThePackageRegisters(string $key): void
    {
        $this->withArguments(['artisan', 'migrate']);

        $this->application()->make('config')->set($key, false);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`' . $key . '` must be a connection name');

        (new IamServiceProvider($this->application()))->register();
    }

    /**
     * Any other console command refuses a mismatch.
     *
     * @return void
     */
    public function testAMismatchIsRefusedWhileAnotherCommandRuns(): void
    {
        $this->withArguments(['artisan', 'migrate']);
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'SSO_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->expectException(StorageConnectionMismatchException::class);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class]);
    }

    /**
     * Outside the console a mismatch is refused, whatever the process's
     * arguments name.
     *
     * @return void
     */
    public function testAMismatchIsRefusedOutsideTheConsole(): void
    {
        $this->withArguments(['artisan', 'config:clear']);
        $this->withEnvironment(['APP_RUNNING_IN_CONSOLE' => 'false', 'IAM_STORAGE_CONNECTION' => self::CONNECTION, 'SSO_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->expectException(StorageConnectionMismatchException::class);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class]);
    }

    /**
     * The binding rule's outcome is kept in the container for the checks; with
     * no capability declaring a seam yet, it bound and kept nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheBindingRulesOutcomeIsKeptForTheChecks(): void
    {
        $outcome = $this->app?->make(BindingOutcome::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertSame([], $outcome->bound);
        self::assertSame([], $outcome->kept);
        self::assertSame($outcome, $this->app?->make(BindingOutcome::class));
    }

    /**
     * Registered once the application has booted, the package settles at once,
     * since a booting callback registered then would never run: a member key
     * naming another connection is refused there and then.
     *
     * @return void
     */
    public function testALateRegistrationRefusesAMismatchAtOnce(): void
    {
        $app = $this->application();

        $app->make('config')->set(StorageConnection::KEY, self::CONNECTION);
        $app->make('config')->set('sso.storage.connection', self::ELSEWHERE);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('sso.storage.connection names [elsewhere], but iam.storage.connection names [testing]');

        $app->register(IamServiceProvider::class, true);
    }

    /**
     * A late registration applies the binding rule again at once, and leaves no
     * booting callback behind.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testALateRegistrationSettlesAtOnceAndLeavesNoBootingCallback(): void
    {
        $app       = $this->application();
        $before    = $app->make(BindingOutcome::class);
        $callbacks = new \ReflectionProperty(FoundationApplication::class, 'bootingCallbacks');
        $count     = count((array) $callbacks->getValue($app));

        $app->register(IamServiceProvider::class, true);

        self::assertNotSame($before, $app->make(BindingOutcome::class));
        self::assertCount($count, (array) $callbacks->getValue($app));
    }

    /**
     * The package settles in the booting phase, before the first provider
     * boots, in every provider order, so a binding made in any `boot()` comes
     * after the binding rule.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testThePackageSettlesBeforeAnyProviderBoots(array $providers): void
    {
        $this->bootInOrder([RecordsSettlementWhileBooting::class, ...$providers]);

        self::assertTrue($this->application()->make(RecordsSettlementWhileBooting::RECORDED));
    }

    /**
     * Registered from another provider's `boot()`, once the booting callbacks
     * have run, the package settles from its own `boot()`: the binding rule's
     * outcome is kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testARegistrationWhileTheApplicationBootsSettlesFromItsOwnBoot(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, RegistersIamWhileBooting::class]);

        $app = $this->application();

        self::assertTrue($app->providerIsLoaded(IamServiceProvider::class));
        self::assertInstanceOf(BindingOutcome::class, $app->make(BindingOutcome::class));
    }

    /**
     * Registered while the application boots, the package still refuses a
     * member key naming another connection.
     *
     * @return void
     */
    public function testARegistrationWhileTheApplicationBootsRefusesAMismatch(): void
    {
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'MFA_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('mfa.storage.connection names [elsewhere], but iam.storage.connection names [testing]');

        $this->bootInOrder([...self::MEMBER_PROVIDERS, RegistersIamWhileBooting::class]);
    }

    /**
     * The package settles once: booting its provider again keeps the outcome
     * the booting phase kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThePackageSettlesOnlyOnce(): void
    {
        $app      = $this->application();
        $outcome  = $app->make(BindingOutcome::class);
        $provider = $app->getProvider(IamServiceProvider::class);

        self::assertInstanceOf(IamServiceProvider::class, $provider);

        $provider->boot();

        self::assertSame($outcome, $app->make(BindingOutcome::class));
    }

    /**
     * The worker reset listeners are registered for Octane's workers and
     * requests, by the events' names, and for the queue's jobs.
     *
     * @return void
     */
    public function testTheWorkerResetListenersAreRegistered(): void
    {
        $listeners = Event::getRawListeners();

        self::assertContains(ResetWhenWorkerStarts::class, $listeners[ResetWhenWorkerStarts::EVENT] ?? []);
        self::assertContains(ResetBetweenRequests::class, $listeners[ResetBetweenRequests::EVENT] ?? []);
        self::assertContains(ResetBeforeJob::class, $listeners[JobProcessing::class] ?? []);
    }

    /**
     * With the switch missing from the configuration, the worker reset is on.
     *
     * @return void
     */
    #[DefineEnvironment('removeTheResetSwitch')]
    public function testTheWorkerResetIsOnWhenTheSwitchIsMissing(): void
    {
        self::assertFalse($this->config()->has('iam.workers.reset'));
        self::assertContains(ResetBetweenRequests::class, Event::getRawListeners()[ResetBetweenRequests::EVENT] ?? []);
    }

    /**
     * With the worker reset turned off, neither listener is registered.
     *
     * @return void
     */
    #[DefineEnvironment('turnTheResetOff')]
    public function testTurningTheWorkerResetOffRegistersNeitherListener(): void
    {
        $listeners = Event::getRawListeners();

        self::assertArrayNotHasKey(ResetWhenWorkerStarts::EVENT, $listeners);
        self::assertArrayNotHasKey(ResetBetweenRequests::EVENT, $listeners);
        self::assertNotContains(ResetBeforeJob::class, $listeners[JobProcessing::class] ?? []);
    }

    /**
     * Rows of `[IAM_WORKERS_RESET, whether the reset is on]`: the values that
     * turn it off, and those that leave it on, an empty, a null or an
     * unrecognised one among them.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideWorkerResetSwitches(): iterable
    {
        yield '0' => ['0', false];

        yield 'false' => ['false', false];

        yield 'off' => ['off', false];

        yield 'no' => ['no', false];

        yield '1' => ['1', true];

        yield 'true' => ['true', true];

        yield 'on' => ['on', true];

        yield 'empty' => ['', true];

        yield 'null' => ['null', true];

        yield 'unrecognised' => ['sometimes', true];
    }

    /**
     * The switch is read as the environment fills it, so turning the reset off
     * with `0`, or leaving any value it does not recognise, boots and turns it
     * off or leaves it on rather than refusing the value.
     *
     * @param  string  $value
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideWorkerResetSwitches')]
    public function testTheWorkerResetSwitchIsReadAsTheEnvironmentFillsIt(string $value, bool $on): void
    {
        $this->withEnvironment(['IAM_WORKERS_RESET' => $value]);
        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class]);

        $listeners = Event::getRawListeners();

        self::assertSame($on, in_array(ResetWhenWorkerStarts::class, $listeners[ResetWhenWorkerStarts::EVENT] ?? [], true));
        self::assertSame($on, in_array(ResetBetweenRequests::class, $listeners[ResetBetweenRequests::EVENT] ?? [], true));
        self::assertSame($on, in_array(ResetBeforeJob::class, $listeners[JobProcessing::class] ?? [], true));
    }

    /**
     * In the console, the configuration file is offered for publishing under
     * the `iam-config` tag.
     *
     * @return void
     */
    public function testTheConfigurationIsPublishedUnderItsTag(): void
    {
        self::assertSame(
            [self::configurationFile() => $this->application()->configPath('iam.php')],
            ServiceProvider::pathsToPublish(IamServiceProvider::class, 'iam-config'),
        );
    }

    /**
     * Outside the console, nothing is offered for publishing.
     *
     * @return void
     */
    public function testNothingIsPublishedOutsideTheConsole(): void
    {
        $app = \Mockery::mock(FoundationApplication::class)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturnFalse();

        $publishes = new \ReflectionProperty(ServiceProvider::class, 'publishes');
        $groups    = new \ReflectionProperty(ServiceProvider::class, 'publishGroups');
        $saved     = [$publishes->getValue(), $groups->getValue()];

        $publishes->setValue(null, []);
        $groups->setValue(null, []);

        try {
            (new \ReflectionMethod(IamServiceProvider::class, 'registerPublishing'))->invoke(new IamServiceProvider($app));

            self::assertSame([], ServiceProvider::pathsToPublish(IamServiceProvider::class));
        } finally {
            $publishes->setValue(null, $saved[0]);
            $groups->setValue(null, $saved[1]);
        }
    }

    /**
     * Remove the worker reset's switch from the configuration, as the package
     * has merged it.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function removeTheResetSwitch(Application $app): void
    {
        $app->make('config')->set('iam.workers', []);
    }

    /**
     * Turn the worker reset off.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function turnTheResetOff(Application $app): void
    {
        $app->make('config')->set('iam.workers.reset', false);
    }

    /**
     * Return the path the provider merges and publishes its configuration from.
     *
     * @return string
     */
    private static function configurationFile(): string
    {
        return dirname((string) (new \ReflectionClass(IamServiceProvider::class))->getFileName()) . '/../config/iam.php';
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
     * Replace the process's arguments, as the console reads them, until the
     * test ends.
     *
     * @param  list<string>  $arguments
     * @return void
     */
    private function withArguments(array $arguments): void
    {
        /** @var list<string> $argv */
        $argv = $_SERVER['argv'] ?? [];

        $this->argv ??= $argv;
        $_SERVER['argv'] = $arguments;
    }

    /**
     * Return the booted application.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function application(): FoundationApplication
    {
        $app = $this->app;

        self::assertInstanceOf(FoundationApplication::class, $app);

        return $app;
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
