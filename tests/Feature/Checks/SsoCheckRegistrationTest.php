<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\Foundation\Env;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Iam\Checks\SsoCheckRegistration;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\Config\Checks\FeaturesCheck;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;
use SineMacula\Laravel\Sso\Exceptions\InvalidConfigurationException;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Fixtures\Providers\HandsOffUnlinkedSignInsWhileRegistering;
use Tests\Fixtures\Providers\RegistersAnIamSsoCheck;
use Tests\Fixtures\Providers\RegistersIamWhileBooting;
use Tests\Fixtures\Providers\RegistersSsoOnceBooted;
use Tests\TestCase;

/**
 * Feature tests for registering this package's checks of SSO's side with SSO's
 * own configuration checks (IAM-10.3), through SSO's registration point rather
 * than a rebinding of its checker: once, under `iam`, in every provider order,
 * after SSO's own, once the application has booted, never over a check the
 * application registered under the same subject from a provider of its own;
 * and reported by `sso:check` only while SSO is in use.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoCheckRegistration::class)]
final class SsoCheckRegistrationTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var list<class-string<\Illuminate\Support\ServiceProvider>> Every member's provider, in the order Composer discovers them, SSO's apart. */
    private const array MEMBERS_WITHOUT_SSO = [
        AuditLogServiceProvider::class,
        AuthenticationServiceProvider::class,
        AuthorizationServiceProvider::class,
        MfaServiceProvider::class,
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
     * Every provider order the suite supports, with this package's provider
     * registered from another provider's `boot()` once SSO's has booted too.
     *
     * @return iterable<string, array{list<class-string<\Illuminate\Support\ServiceProvider>>}>
     */
    public static function provideEveryBootOrder(): iterable
    {
        yield from self::provideProviderOrders();

        yield 'this package registered while booting, after SSO' => [[...self::MEMBERS_WITHOUT_SSO, SsoServiceProvider::class, RegistersIamWhileBooting::class]];
    }

    /**
     * Outside the console, SSO's boot check, queued as SSO boots, runs the
     * bridge in every provider order, this package's registered from another
     * provider's `boot()` after SSO's has booted included: with SSO in use and
     * an SSO application's `unlinked_handoffs` on, boot is refused with the
     * bridge's problem under `[iam]`.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideEveryBootOrder')]
    public function testSsosBootCheckRunsTheBridgeOutsideTheConsoleInEveryOrder(array $providers): void
    {
        $this->withEnvironment(['APP_RUNNING_IN_CONSOLE' => 'false', 'SSO_SAML2' => 'true']);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('[iam] `' . HandsOffUnlinkedSignInsWhileRegistering::KEY . '` must stay off under laravel-iam');

        $this->bootInOrder([HandsOffUnlinkedSignInsWhileRegistering::class, ...$providers]);
    }

    /**
     * SSO's provider registered once the application has booted, after this
     * package's addition found no SSO checks to add to, still has the bridge
     * added to its checks as its checker is first resolved, as a worker command
     * or `sso:check` resolves it, so `sso:check` runs it.
     *
     * @return void
     */
    public function testSsoRegisteredOnceBootedStillRunsTheBridge(): void
    {
        $this->withArguments(['artisan', 'iam:check']);

        $this->bootInOrder([...self::MEMBERS_WITHOUT_SSO, IamServiceProvider::class, RegistersSsoOnceBooted::class]);

        $app = $this->application();

        self::assertTrue(SsoCheckRegistration::isInForce($app));
        self::assertSame([...SsoServiceProvider::CONFIGURATION_CHECKS, SsoCheckRegistration::SUBJECT => SsoBridgeCheck::class], $app->make(ConfigurationChecks::class)->all());
    }

    /**
     * The check is registered under `iam`, once, after every check of SSO's
     * own, in every provider order, and SSO's checker is still SSO's.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheCheckIsRegisteredAfterSsosOwnInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers);

        $app = $this->application();

        self::assertSame([...SsoServiceProvider::CONFIGURATION_CHECKS, SsoCheckRegistration::SUBJECT => SsoBridgeCheck::class], $app->make(ConfigurationChecks::class)->all());
        self::assertInstanceOf(ConfigurationChecker::class, $app->make(ConfigurationChecker::class));
    }

    /**
     * A check the application registers under `iam` from a provider of its own,
     * registered after the packages' as Laravel registers an application's
     * providers, is kept in every order of the packages' providers: resolving
     * SSO's checks, as its boot check, a worker command or `sso:check` does,
     * never throws, the bridge is not in force, and `iam:check` runs it itself.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    public function testACheckTheApplicationRegistersAfterThePackagesIsKept(array $providers): void
    {
        $this->bootInOrder([...$providers, RegistersAnIamSsoCheck::class]);

        $app = $this->application();

        self::assertSame(
            [...SsoServiceProvider::CONFIGURATION_CHECKS, SsoCheckRegistration::SUBJECT => RegistersAnIamSsoCheck::CHECK],
            $app->make(ConfigurationChecks::class)->all(),
        );
        self::assertFalse(SsoCheckRegistration::isInForce($app));
        self::assertStringContainsString('[iam] ', $this->ssoCheck());

        $app->make('config')->set('sso.features.saml2', true);
        $app->make('config')->set('sso.applications.api.unlinked_handoffs', true);

        $output = new BufferedOutput;

        Artisan::call('iam:check', [], $output);

        self::assertStringContainsString(
            '[sso] `sso.applications.api.unlinked_handoffs` must stay off under laravel-iam: an unlinked result is provisioned or refused, never handed off.',
            $output->fetch(),
        );
    }

    /**
     * Registered once SSO's checks are resolved already, the check is added at
     * once; a check registered under `iam` before it is kept.
     *
     * @return void
     */
    public function testARegistrationOnceResolvedAddsAtOnceAndKeepsTheApplicationsCheck(): void
    {
        $app = $this->application();

        $app->instance(ConfigurationChecks::class, new ConfigurationChecks(['features' => FeaturesCheck::class]));

        SsoCheckRegistration::register($app);

        self::assertSame(['features' => FeaturesCheck::class, 'iam' => SsoBridgeCheck::class], $app->make(ConfigurationChecks::class)->all());

        $app->instance(ConfigurationChecks::class, new ConfigurationChecks(['iam' => FeaturesCheck::class]));

        SsoCheckRegistration::register($app);

        self::assertSame(['iam' => FeaturesCheck::class], $app->make(ConfigurationChecks::class)->all());
    }

    /**
     * SSO's checker resolved before the application has booted adds nothing, so
     * a check the application registers under `iam` while it boots is still
     * kept; once it has booted, each resolution of the checker adds the check
     * to SSO's checks first, so the checker is built with it, and adds nothing
     * while SSO's provider has not registered.
     *
     * @return void
     */
    public function testResolvingSsosCheckerAddsTheCheckOnlyOnceBooted(): void
    {
        $app = new Application(dirname(__DIR__, 3));

        $app->instance(ConfigurationChecks::class, new ConfigurationChecks(['features' => FeaturesCheck::class]));
        $app->bind(
            ConfigurationChecker::class,
            static fn (Application $app): ConfigurationChecker => new ConfigurationChecker($app, $app->make(ConfigurationChecks::class)->all()),
        );

        SsoCheckRegistration::register($app);

        $app->make(ConfigurationChecker::class);

        self::assertSame(['features' => FeaturesCheck::class], $app->make(ConfigurationChecks::class)->all());

        $app->boot();

        $app->instance(ConfigurationChecks::class, new ConfigurationChecks(['features' => FeaturesCheck::class]));

        self::assertTrue(SsoCheckRegistration::isInForce($app));
        self::assertSame(['features' => FeaturesCheck::class, 'iam' => SsoBridgeCheck::class], $app->make(ConfigurationChecks::class)->all());

        $app->offsetUnset(ConfigurationChecks::class);

        self::assertFalse(SsoCheckRegistration::isInForce($app));
    }

    /**
     * A checker the application binds to what is no SSO checker, an object of
     * another class or no object at all, holds no checks this package can read,
     * so the bridge is not in force there.
     *
     * @return void
     */
    public function testACheckerThatIsNoSsoCheckerIsNotInForce(): void
    {
        $app = $this->application();

        $app->bind(ConfigurationChecker::class, static fn (): \stdClass => new \stdClass);

        self::assertFalse(SsoCheckRegistration::isInForce($app));

        $app->bind(ConfigurationChecker::class, static fn (): string => SsoBridgeCheck::class);

        self::assertFalse(SsoCheckRegistration::isInForce($app));
    }

    /**
     * While SSO's provider has not registered, nothing is resolved or added
     * once the application boots.
     *
     * @return void
     */
    public function testNothingIsAddedWhileSsosProviderHasNotRegistered(): void
    {
        $app = new Application(dirname(__DIR__, 3));

        SsoCheckRegistration::register($app);

        $app->boot();

        self::assertTrue($app->isBooted());
        self::assertFalse($app->resolved(ConfigurationChecks::class));
    }

    /**
     * `sso:check` reports the check under `[iam]`: not enabled while SSO is not
     * in use, and each problem it finds once it is.
     *
     * @return void
     */
    public function testSsosCheckReportsIt(): void
    {
        self::assertStringContainsString('[iam] not enabled', $this->ssoCheck());

        $this->application()->make('config')->set('sso.features.saml2', true);
        $this->application()->make('config')->set('sso.applications.api.unlinked_handoffs', true);

        self::assertStringContainsString(
            '[iam] `sso.applications.api.unlinked_handoffs` must stay off under laravel-iam: an unlinked result is provisioned or refused, never handed off.',
            $this->ssoCheck(),
        );
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
     * The application the test booted.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function application(): Application
    {
        $app = $this->app;

        self::assertInstanceOf(Application::class, $app);

        return $app;
    }

    /**
     * Run `sso:check` and return what it printed.
     *
     * @return string
     */
    private function ssoCheck(): string
    {
        $output = new BufferedOutput;

        Artisan::call('sso:check', [], $output);

        return $output->fetch();
    }
}
