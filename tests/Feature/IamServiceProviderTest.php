<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\GenericUser;
use Illuminate\Config\Repository;
use Illuminate\Console\Application as Artisan;
use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Application as FoundationApplication;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use Orchestra\Testbench\Attributes\WithConfig;
use Orchestra\Testbench\Foundation\Env;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\HeldActorReader;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Iam\Audit\AuthenticationActorReader;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextAdapter;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\GrantScopeAdapter;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Console\CheckCommand;
use SineMacula\Laravel\Iam\Console\InstallCommand;
use SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException;
use SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException;
use SineMacula\Laravel\Iam\IamManager;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Mfa\ContextSeams;
use SineMacula\Laravel\Iam\Mfa\FactorCodeCallers;
use SineMacula\Laravel\Iam\Mfa\MfaContextContributor;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\PasskeySeams;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Iam\Sso\RenewalRecorder;
use SineMacula\Laravel\Iam\Sso\SsoContextContributor;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Iam\Tenancy\UnknownGrantScope;
use SineMacula\Laravel\Iam\Workers\ResetBeforeJob;
use SineMacula\Laravel\Iam\Workers\ResetWhenWorkerStarts;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Database\StorageConnection as SsoStorageConnection;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Concerns\ReadsRawListeners;
use Tests\Fixtures\Providers\RecordsAuthorizationContextWhileBooting;
use Tests\Fixtures\Providers\RecordsSettlementWhileBooting;
use Tests\Fixtures\Providers\RegistersIamWhileBooting;
use Tests\Fixtures\Providers\RegistersSsoOnceBooted;
use Tests\Fixtures\Providers\RegistersSsoWhileBooting;
use Tests\Fixtures\Storage\ChangesTheSharedConnection;
use Tests\Fixtures\Storage\ChangesTheSharedConnectionWhileBooting;
use Tests\Fixtures\Storage\PointsMfaElsewhereWhileBooting;
use Tests\Fixtures\Storage\PublishesSsoConfigurationWithoutStorage;
use Tests\Fixtures\Storage\RecordsMemberConnections;
use Tests\TestCase;

/**
 * Feature tests for the package service provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IamServiceProvider::class)]
final class IamServiceProviderTest extends TestCase
{
    use PermutesProviderOrder, ReadsRawListeners;

    /** @var string A connection no key in these tests is aligned to. */
    private const string ELSEWHERE = 'elsewhere';

    /** @var list<string> The environment variables this test set, cleared once its application is destroyed. */
    private array $environment = [];

    /**
     * Destroy the application and clear the test's environment variables.
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
     * The package's configuration is merged under `iam`.
     *
     * @return void
     */
    public function testTheConfigurationIsMergedUnderIam(): void
    {
        self::assertSame(require self::configurationFile(), $this->config()->get('iam'));
    }

    /**
     * `iam:check` is declared as composing `authorization:check`.
     *
     * @return void
     */
    public function testIamCheckIsDeclaredAsComposingAuthorizationsCheck(): void
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        self::assertTrue(Declarations::of($app)->isComposing(CheckCommand::NAME));
    }

    /**
     * MFA's factor code callers are one instance per request or job.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheFactorCodeCallersAreScoped(): void
    {
        $app     = $this->application();
        $callers = $app->make(FactorCodeCallers::class);

        self::assertSame($callers, $app->make(FactorCodeCallers::class));

        $app->forgetScopedInstances();

        self::assertNotSame($callers, $app->make(FactorCodeCallers::class));
    }

    /**
     * The redemption records are scoped under this package's key.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheRedemptionRecordsAreScoped(): void
    {
        $app = $this->application();

        foreach ([AdmittedRedemptions::class, RenewalRecorder::class] as $class) {

            $record = $app->make($class);

            self::assertSame($record, $app->make(SeamBinding::SCOPED_PREFIX . $class));

            $app->forgetScopedInstances();

            self::assertNotSame($record, $app->make($class));
        }
    }

    /**
     * The worker reset forgets MFA's factor code callers.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheWorkerResetForgetsTheFactorCodeCallers(): void
    {
        $app     = $this->application();
        $callers = $app->make(FactorCodeCallers::class);
        $caller  = CallerContext::nobody('api');
        $binding = $callers->hold(self::factorCodeBinding(), $caller);

        self::assertSame($caller, $app->make(FactorCodeCallers::class)->of($binding));
        self::assertSame($callers, $app->make(SeamBinding::SCOPED_PREFIX . FactorCodeCallers::class));

        $app->make(IamManager::class)->resetWorkerState();

        self::assertNotSame($callers, $app->make(FactorCodeCallers::class));
        self::assertNull($app->make(FactorCodeCallers::class)->of($binding));
    }

    /**
     * The grant scope is authorization's query until something else is bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheGrantScopeIsAuthorizationsQueryUntilSomethingElseIsBound(): void
    {
        $app   = $this->application();
        $scope = $app->make(GrantScope::class);

        self::assertInstanceOf(GrantScopeAdapter::class, $scope);
        self::assertNotSame($scope, $app->make(GrantScope::class));

        $bound = new UnknownGrantScope;

        $app->instance(GrantScope::class, $bound);

        self::assertSame($bound, $app->make(GrantScope::class));
    }

    /**
     * With authorization off, the grant scope is a shared `UnknownGrantScope`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
    public function testTheGrantScopeIsUnknownWithTheAuthorizationSwitchOff(): void
    {
        $app   = $this->application();
        $scope = $app->make(GrantScope::class);

        self::assertInstanceOf(UnknownGrantScope::class, $scope);
        self::assertSame($scope, $app->make(GrantScope::class));
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
     * Audit-log reads the guards through this package's reader.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuditLogReadsTheGuardsThroughTheReader(): void
    {
        self::assertInstanceOf(AuthenticationActorReader::class, $this->application()->make(HeldActorReader::class));
    }

    /**
     * The shared connection is written into the member keys at registration.
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
     * A member registered after this package is aligned as the app boots.
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
     * A member key naming another connection refuses boot.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    public function testAMemberKeyNamingAnotherConnectionRefusesBoot(array $providers): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'MFA_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('mfa.storage.connection names [elsewhere], but iam.storage.connection names [testing]');

        $this->bootInOrder($providers);
    }

    /**
     * A key this package wrote follows a connection changed in a later
     * `register()`.
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
     * A key this package wrote follows a connection changed in a `boot()`.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    #[DefineEnvironment('defineAnotherConnection')]
    public function testAKeyThisPackageWroteFollowsASharedConnectionChangedWhileBooting(array $providers): void
    {
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->bootInOrder([...$providers, ChangesTheSharedConnectionWhileBooting::class]);

        $config = $this->config();

        foreach (StorageConnection::MEMBER_KEYS as $key) {
            self::assertSame(ChangesTheSharedConnectionWhileBooting::CONNECTION, $config->get($key), $key . ' did not follow the shared connection.');
        }
    }

    /**
     * A member key pointed elsewhere in a `boot()` is refused once booted.
     *
     * @return void
     */
    #[DefineEnvironment('defineAnotherConnection')]
    public function testAMemberKeyChangedWhileBootingRefusesBoot(): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION]);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('mfa.storage.connection names [elsewhere], but iam.storage.connection names [testing]');

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, PointsMfaElsewhereWhileBooting::class]);
    }

    /**
     * Rows of `[arguments]` naming a configuration command.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideUncheckedCommands(): iterable
    {
        foreach (['config:cache', 'config:clear', 'config:show', 'help', 'list', 'optimize:clear', 'package:discover'] as $command) {
            yield $command => [['artisan', '-v', $command]];
        }

        yield 'no command' => [['artisan']];

        yield 'no command from another directory' => [['/var/www/artisan']];

        yield 'only options' => [['artisan', '-v', '--no-interaction']];

        yield 'the environment after a space' => [['artisan', '--env', 'production', 'config:clear']];

        yield 'the environment after an equals sign' => [['artisan', '--env=production', 'config:clear']];

        yield 'the environment named twice' => [['artisan', '--env', '--env', 'production', 'config:clear']];

        yield 'the environment without a value' => [['artisan', '-v', '--env']];
    }

    /**
     * A configuration command does not refuse a mismatch.
     *
     * @param  list<string>  $arguments
     * @return void
     */
    #[DataProvider('provideUncheckedCommands')]
    public function testAMismatchIsNotRefusedWhileAConfigurationCommandRuns(array $arguments): void
    {
        $this->withArguments($arguments);
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'SSO_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class]);

        self::assertSame(self::ELSEWHERE, $this->config()->get('sso.storage.connection'));
        self::assertSame(self::CONNECTION, $this->config()->get('mfa.storage.connection'));
        self::assertInstanceOf(GrantScopeAdapter::class, $this->application()->make(GrantScope::class));
    }

    /**
     * Rows of `[variable, key]`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideConnectionKeys(): iterable
    {
        yield 'the shared connection' => ['IAM_STORAGE_CONNECTION', StorageConnection::KEY];

        yield 'a member connection' => ['MFA_STORAGE_CONNECTION', 'mfa.storage.connection'];
    }

    /**
     * A configuration command leaves a connection key that is not a name alone.
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
        self::assertInstanceOf(GrantScopeAdapter::class, $this->application()->make(GrantScope::class));
    }

    /**
     * Any other command refuses a connection key that is not a name.
     *
     * @param  string  $variable
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideConnectionKeys')]
    public function testAConnectionKeyThatIsNotANameRefusesBootWhileAnotherCommandRuns(string $variable, string $key): void
    {
        $this->withArguments(self::CHECKED_COMMAND);
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
     * A connection key that is not a name is refused at registration.
     *
     * @param  string  $key
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideConnectionKeyNames')]
    public function testAConnectionKeyThatIsNotANameIsRefusedAsThePackageRegisters(string $key): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->application()->make('config')->set($key, false);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`' . $key . '` must be a connection name');

        (new IamServiceProvider($this->application()))->register();
    }

    /**
     * Rows of `[arguments]` naming no configuration command.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideCheckedCommands(): iterable
    {
        yield 'a command' => [['artisan', 'migrate']];

        yield 'a test runner' => [['vendor/bin/phpunit']];

        yield 'a test runner given an option and its value together' => [['vendor/bin/phpunit', '--filter=x']];

        yield 'a test runner given only options' => [['vendor/bin/phpunit', '--configuration=phpunit.xml', '--colors=always']];

        yield 'a worker script' => [['worker.php']];

        yield 'a worker script named after Artisan' => [['artisan-worker']];

        yield 'a worker binary' => [['vendor/bin/roadrunner-worker']];

        yield 'no arguments' => [[]];

        yield 'after an option' => [['artisan', '-v', 'migrate']];

        yield 'after the environment' => [['artisan', '--env', 'production', 'migrate']];

        yield 'after an environment named as a configuration command' => [['artisan', '--env', 'config:clear', 'migrate']];

        yield 'after the environment without a value' => [['artisan', '--env', '-v', 'migrate']];
    }

    /**
     * Any other command, or a non-Artisan process, refuses a mismatch.
     *
     * @param  list<string>  $arguments
     * @return void
     */
    #[DataProvider('provideCheckedCommands')]
    public function testAMismatchIsRefusedWhileAnotherCommandRuns(array $arguments): void
    {
        $this->withArguments($arguments);
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'SSO_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->expectException(StorageConnectionMismatchException::class);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class]);
    }

    /**
     * A mismatch is refused outside the console.
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
     * Every adapter on by default is bound over its member's default.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testEveryAdapterIsBoundOverItsMembersDefault(array $providers): void
    {
        $this->bootInOrder($providers);

        $app = $this->application();
        $off = [PasskeyGateway::class, EvidencePolicy::class, TenantMembership::class, LinkEligibility::class, PrincipalScope::class];

        FakeOneTimeCodeSender::fake($app);

        foreach ($this->rows() as $row) {

            self::assertSame(in_array($row->abstract, $off, true), $row->holdsDefault($app), $row->abstract);

            if (!$row->on) {
                continue;
            }

            self::assertInstanceOf($row->adapter, $app->make($row->abstract), $row->abstract);
        }
    }

    /**
     * The application's own binding wins over the adapter.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheApplicationsBindingWinsOverTheAdapter(array $providers): void
    {
        $bindings  = [];
        $instances = [];

        foreach ($this->rows() as $row) {

            $instance = \Mockery::mock($row->abstract)->shouldIgnoreMissing([]);

            $instances[$row->abstract] = $instance;
            $bindings[$row->abstract]  = static fn (): object => $instance;
        }

        foreach (['before' => [$bindings, []], 'after' => [[], $bindings]] as $when => [$before, $after]) {

            $this->bootInOrder($providers, $before, $after);

            foreach ($instances as $abstract => $instance) {
                self::assertSame($instance, $this->application()->make($abstract), $when . ': ' . $abstract);
            }
        }
    }

    /**
     * A registration after boot refuses a mismatch at once.
     *
     * @return void
     */
    public function testALateRegistrationRefusesAMismatchAtOnce(): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $app = $this->application();

        $app->make('config')->set(StorageConnection::KEY, self::CONNECTION);
        $app->make('config')->set('sso.storage.connection', self::ELSEWHERE);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('sso.storage.connection names [elsewhere], but iam.storage.connection names [testing]');

        $app->register(IamServiceProvider::class, true);
    }

    /**
     * A registration after boot binds the seams at once.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testALateRegistrationSettlesAtOnceAndLeavesNoBootingCallback(): void
    {
        $app       = $this->application();
        $callbacks = new \ReflectionProperty(FoundationApplication::class, 'bootingCallbacks');
        $count     = count((array) $callbacks->getValue($app));

        $app->offsetUnset(GrantScope::class);
        $app->register(IamServiceProvider::class, true);

        self::assertInstanceOf(GrantScopeAdapter::class, $app->make(GrantScope::class));
        self::assertCount($count, (array) $callbacks->getValue($app));
    }

    /**
     * Storage is settled before any provider boots.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testThePackageSettlesBeforeAnyProviderBoots(array $providers): void
    {
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION]);

        $this->bootInOrder([RecordsSettlementWhileBooting::class, ...$providers]);

        self::assertSame(array_fill_keys(StorageConnection::MEMBER_KEYS, self::CONNECTION), $this->application()->make(RecordsSettlementWhileBooting::RECORDED));
    }

    /**
     * The seams are bound before any provider boots.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheSeamsAreBoundBeforeAnyProviderBoots(array $providers): void
    {
        $this->bootInOrder([RecordsAuthorizationContextWhileBooting::class, ...$providers]);

        self::assertSame(AuthenticationContextAdapter::class, $this->application()->make(RecordsAuthorizationContextWhileBooting::RECORDED));
    }

    /**
     * A registration from another provider's `boot()` still binds the seams.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testARegistrationWhileTheApplicationBootsBindsTheSeams(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, RegistersIamWhileBooting::class]);

        $app = $this->application();

        self::assertTrue($app->providerIsLoaded(IamServiceProvider::class));
        self::assertInstanceOf(GrantScopeAdapter::class, $app->make(GrantScope::class));
    }

    /**
     * A registration from another provider's `boot()` refuses a mismatch.
     *
     * @return void
     */
    public function testARegistrationWhileTheApplicationBootsRefusesAMismatch(): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'MFA_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('mfa.storage.connection names [elsewhere], but iam.storage.connection names [testing]');

        $this->bootInOrder([...self::MEMBER_PROVIDERS, RegistersIamWhileBooting::class]);
    }

    /**
     * The package settles only once.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThePackageSettlesOnlyOnce(): void
    {
        $app      = $this->application();
        $provider = $app->getProvider(IamServiceProvider::class);

        self::assertInstanceOf(IamServiceProvider::class, $provider);

        $this->config()->set(StorageConnection::KEY, self::CONNECTION);
        $this->config()->set('sso.storage.connection', self::ELSEWHERE);
        $this->config()->set('mfa.storage.connection', null);

        $app->offsetUnset(GrantScope::class);

        $provider->boot();

        self::assertSame(self::ELSEWHERE, $this->config()->get('sso.storage.connection'));
        self::assertNull($this->config()->get('mfa.storage.connection'));
        self::assertFalse($app->bound(GrantScope::class));
    }

    /**
     * A member registered from a `boot()` is aligned once booted.
     *
     * @return void
     */
    #[DefineEnvironment('defineAnotherConnection')]
    public function testAMemberRegisteredWhileTheApplicationBootsIsAligned(): void
    {
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->bootInOrder([...self::membersWithoutSso(), IamServiceProvider::class, RegistersSsoWhileBooting::class]);

        self::assertSame(self::ELSEWHERE, $this->config()->get('sso.storage.connection'));
        self::assertSame(self::ELSEWHERE, SsoStorageConnection::name());
    }

    /**
     * A member registered from a `boot()` has a mismatch refused.
     *
     * @return void
     */
    public function testAMemberRegisteredWhileTheApplicationBootsRefusesAMismatch(): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'SSO_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('sso.storage.connection names [elsewhere], but iam.storage.connection names [testing]');

        $this->bootInOrder([...self::membersWithoutSso(), IamServiceProvider::class, RegistersSsoWhileBooting::class]);
    }

    /**
     * A member registered from a `boot()` keeps its connection until it merges.
     *
     * @return void
     */
    public function testAMemberRegisteredWhileTheApplicationBootsKeepsItsOwnConnectionUntilItMerges(): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::CONNECTION, 'SSO_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->expectException(StorageConnectionMismatchException::class);
        $this->expectExceptionMessage('sso.storage.connection names [elsewhere], but iam.storage.connection names [testing]');

        $this->bootInOrder([PublishesSsoConfigurationWithoutStorage::class, ...self::membersWithoutSso(), IamServiceProvider::class, RegistersSsoWhileBooting::class]);
    }

    /**
     * A member registered only after boot refuses boot.
     *
     * @return void
     */
    public function testAMemberRegisteredOnceTheApplicationHasBootedRefusesBoot(): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->expectException(MemberNotRegisteredException::class);
        $this->expectExceptionMessage(SsoServiceProvider::class . ' had not registered when the application finished booting');

        $this->bootInOrder([...self::membersWithoutSso(), IamServiceProvider::class, RegistersSsoOnceBooted::class]);
    }

    /**
     * A registration after boot refuses a missing member at once.
     *
     * @return void
     */
    public function testALateRegistrationRefusesAMissingMemberAtOnce(): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->bootInOrder(self::membersWithoutSso());

        $this->expectException(MemberNotRegisteredException::class);
        $this->expectExceptionMessage(SsoServiceProvider::class . ' had not registered when the application finished booting');

        $this->application()->register(IamServiceProvider::class, true);
    }

    /**
     * A configuration command does not refuse a missing member.
     *
     * @return void
     */
    #[DefineEnvironment('defineAnotherConnection')]
    public function testAMissingMemberIsNotRefusedWhileAConfigurationCommandRuns(): void
    {
        $this->withArguments(['artisan', 'config:clear']);
        $this->withEnvironment(['IAM_STORAGE_CONNECTION' => self::ELSEWHERE]);

        $this->bootInOrder([...self::membersWithoutSso(), IamServiceProvider::class]);

        self::assertTrue($this->application()->isBooted());
        self::assertSame(self::ELSEWHERE, $this->config()->get('mfa.storage.connection'));
    }

    /**
     * The `mfa` and `sso` contributors are registered once booted.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheContextContributorsAreRegisteredOnceBooted(): void
    {
        $registered = $this->app?->make(ContextContributors::class)->registered() ?? self::fail('The application has not booted.');

        self::assertSame(['mfa' => MfaContextContributor::class, 'sso' => SsoContextContributor::class], $registered);
    }

    /**
     * The worker reset listeners are registered for Octane and the queue.
     *
     * @return void
     */
    public function testTheWorkerResetListenersAreRegistered(): void
    {
        self::assertContains(ResetWhenWorkerStarts::class, self::rawListenersOf(ResetWhenWorkerStarts::EVENT));
        self::assertContains(ResetBeforeJob::class, self::rawListenersOf(JobProcessing::class));
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
        self::assertContains(ResetBeforeJob::class, self::rawListenersOf(JobProcessing::class));
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
        self::assertNotContains(ResetBeforeJob::class, self::rawListenersOf(JobProcessing::class));
    }

    /**
     * Rows of `[IAM_WORKERS_RESET, whether the reset is on]`.
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
     * The worker reset switch is read leniently, as the environment fills it.
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

        self::assertSame($on, in_array(ResetWhenWorkerStarts::class, self::rawListenersOf(ResetWhenWorkerStarts::EVENT), true));
        self::assertSame($on, in_array(ResetBeforeJob::class, self::rawListenersOf(JobProcessing::class), true));
    }

    /**
     * The configuration is published under the `iam-config` tag.
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
     * `iam:install` and `iam:check` are registered in the console.
     *
     * @return void
     */
    public function testTheCommandsAreRegisteredInTheConsole(): void
    {
        $commands = $this->application()->make(ConsoleKernel::class)->all();

        self::assertInstanceOf(InstallCommand::class, $commands[InstallCommand::NAME] ?? null);
        self::assertInstanceOf(CheckCommand::class, $commands[CheckCommand::NAME] ?? null);
    }

    /**
     * Every capability's seams are bound and checked, in order.
     *
     * @return void
     */
    public function testEveryCapabilitysSeamsAreProvided(): void
    {
        self::assertSame(
            [MfaSeams::class, PasskeySeams::class, ContextSeams::class, SsoSeams::class, TenancySeams::class, AuthorizationSeams::class],
            IamServiceProvider::seamProviders(),
        );
    }

    /**
     * Nothing is published or registered outside the console.
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

        $bootstrappers = new \ReflectionProperty(Artisan::class, 'bootstrappers');
        $starting      = $bootstrappers->getValue();

        try {
            (new \ReflectionMethod(IamServiceProvider::class, 'registerConsole'))->invoke(new IamServiceProvider($app));

            self::assertSame([], ServiceProvider::pathsToPublish(IamServiceProvider::class));
            self::assertSame($starting, $bootstrappers->getValue());
        } finally {
            $publishes->setValue(null, $saved[0]);
            $groups->setValue(null, $saved[1]);
        }
    }

    /**
     * Remove the worker reset switch from the configuration.
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
     * Configure a second connection beside the default one.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function defineAnotherConnection(Application $app): void
    {
        $app->make('config')->set('database.connections.' . self::ELSEWHERE, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
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
     * Every member's provider but `laravel-sso`'s.
     *
     * @return list<class-string<\Illuminate\Support\ServiceProvider>>
     */
    private static function membersWithoutSso(): array
    {
        return array_values(array_diff(self::MEMBER_PROVIDERS, [SsoServiceProvider::class]));
    }

    /**
     * A factor code binding for a caller to be kept beside.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     */
    private static function factorCodeBinding(): FactorCodeBinding
    {
        $identity = new class (['id' => 7]) extends GenericUser implements Identity {};

        return new FactorCodeBinding(new ProofBinding($identity, 'api', 'session-1', Purpose::STEP_UP), 'factor-1', new Channel(ChannelKind::SMS, '+447700900123'));
    }

    /**
     * Set environment variables, cleared once the test ends.
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

    /**
     * Every capability's rows.
     *
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function rows(): array
    {
        $app  = $this->application();
        $rows = [];

        foreach (IamServiceProvider::seamProviders() as $provider) {
            foreach ($app->make($provider)->seams($this->config()) as $row) {
                $rows[] = $row;
            }
        }

        return $rows;
    }
}
