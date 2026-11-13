<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\AuditLog\Contracts\HeldActorReader;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Iam\Audit\AuditRegistrations;
use SineMacula\Laravel\Iam\Audit\AuthenticationActorReader;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextKeys;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\GrantScopeAdapter;
use SineMacula\Laravel\Iam\Authorization\InsufficientAuthenticationMapping;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Console\CheckCommand;
use SineMacula\Laravel\Iam\Console\InstallCommand;
use SineMacula\Laravel\Iam\Mfa\ContextSeams;
use SineMacula\Laravel\Iam\Mfa\FactorCodeCallers;
use SineMacula\Laravel\Iam\Mfa\MfaContextContributor;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\PasskeySeams;
use SineMacula\Laravel\Iam\Provisioning\ProvisionOnUnlinkedResult;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Iam\Sso\RenewalRecorder;
use SineMacula\Laravel\Iam\Sso\SsoContextContributor;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Storage\ConnectionAlignment;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Iam\Tenancy\UnknownGrantScope;
use SineMacula\Laravel\Iam\Workers\ResetBeforeJob;
use SineMacula\Laravel\Iam\Workers\ResetWhenWorkerStarts;
use SineMacula\Laravel\Mfa\Context\AuthenticationContextContributor as MfaContributor;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;

/**
 * Registers the package, binds its adapters over the members' seams and aligns
 * every member on one storage connection.
 *
 * Seams are bound and storage settled in the booting phase, once every member
 * has merged its configuration, and storage is checked again once booted, since
 * a provider's `boot()` can still change it. A mismatch or a missing member
 * refuses boot, except under the configuration commands and `iam:check`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class IamServiceProvider extends ServiceProvider
{
    /** @var list<string> The console commands neither a storage mismatch nor a missing member refuses. */
    private const array UNCHECKED_COMMANDS = [
        'config:cache',
        'config:clear',
        'config:show',
        'help',
        CheckCommand::NAME,
        'list',
        'optimize:clear',
        'package:discover',
    ];

    /** @var string The command Artisan runs when none is named. */
    private const string DEFAULT_COMMAND = 'list';

    /** @var string The script that runs the default command when none is named. */
    private const string ARTISAN = 'artisan';

    /** @var string The only global console option that takes a value. */
    private const string ENVIRONMENT_OPTION = '--env';

    /** @var array<string, ?string> The member keys this provider wrote, with the value written last. */
    private array $written = [];

    /** @var bool Whether the seams are bound and storage settled. */
    private bool $settled = false;

    /** @var bool Whether SSO was on when the seams were bound. */
    private bool $ssoOn = false;

    /** @var bool Whether MFA was on when the seams were bound. */
    private bool $mfaOn = false;

    /** @var bool Whether authorization was on when the seams were bound. */
    private bool $authorizationOn = false;

    /**
     * Register the configuration, request records and storage settlement.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/iam.php', 'iam');

        $this->registerManager();
        $this->registerFactorCodeCallers();
        $this->registerRedemptionRecords();

        $this->app->singleton(HeldActorReader::class, AuthenticationActorReader::class);

        $this->written = $this->alignStorage($this->app->make(ConnectionAlignment::class), $this->app->make(ConfigRepository::class), $this->app);

        AuthenticationContextKeys::register($this->app);
        $this->registerSettlement();

        // laravel-authorization defers its boot errors to `iam:check`.
        Declarations::of($this->app)->composingCommand(CheckCommand::NAME);
    }

    /**
     * Settle, then register the audit trail, contributors and listeners.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException
     * @throws \LogicException
     */
    public function boot(): void
    {
        $this->settle();
        AuditRegistrations::register($this->app, !self::isRunningUncheckedCommand($this->app));
        $this->registerContextContributors();
        ProvisionOnUnlinkedResult::listen();
        InsufficientAuthenticationMapping::register($this->app, $this->authorizationOn && $this->mfaOn);
        $this->registerListeners();
        $this->registerConsole();
    }

    /**
     * The capabilities whose seams are bound.
     *
     * @return list<class-string<\SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams>>
     *
     * @internal
     */
    public static function seamProviders(): array
    {
        return [
            MfaSeams::class,
            PasskeySeams::class,
            ContextSeams::class,
            SsoSeams::class,
            TenancySeams::class,
            AuthorizationSeams::class,
        ];
    }

    /**
     * Register the `iam` manager behind the facade.
     *
     * @return void
     */
    protected function registerManager(): void
    {
        $this->app->singleton('iam', static fn (): IamManager => new IamManager);
        $this->app->alias('iam', IamManager::class);
    }

    /**
     * Register MFA's factor code callers, scoped so the worker reset drops
     * them.
     *
     * @return void
     */
    protected function registerFactorCodeCallers(): void
    {
        $key = SeamBinding::SCOPED_PREFIX . FactorCodeCallers::class;

        $this->app->scoped($key, static fn (): FactorCodeCallers => new FactorCodeCallers);
        $this->app->bind(FactorCodeCallers::class, static fn (Application $app): mixed => $app->make($key));
    }

    /**
     * Register SSO's request records, scoped so the worker reset forgets them.
     *
     * @return void
     */
    protected function registerRedemptionRecords(): void
    {
        foreach ([AdmittedRedemptions::class, RenewalRecorder::class] as $record) {

            $key = SeamBinding::SCOPED_PREFIX . $record;

            $this->app->scoped($key, static fn (): object => new $record);
            $this->app->bind($record, static fn (Application $app): mixed => $app->make($key));
        }
    }

    /**
     * Register the `mfa` and `sso` contributors once every provider has booted.
     *
     * A member registered from another provider's `boot()` binds its registry
     * only then.
     *
     * @return void
     */
    protected function registerContextContributors(): void
    {
        $this->app->booted(function (): void {

            $this->registerContributor($this->mfaOn, MfaContributor::NAMESPACE, MfaContextContributor::class);
            $this->registerContributor($this->ssoOn, AuthenticationContext::NAMESPACE, SsoContextContributor::class);
        });
    }

    /**
     * Settle in the booting phase, or from `boot()` when registered after it.
     *
     * @return void
     */
    protected function registerSettlement(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        if ($app->isBooted()) {
            return;
        }

        $app->booting(function (): void {

            $this->settle();
        });
    }

    /**
     * Register the Octane and queue worker reset listeners, unless turned off.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function registerListeners(): void
    {
        if (!self::isWorkerResetOn($this->app->make(ConfigRepository::class)->get('iam.workers.reset'))) {
            return;
        }

        Event::listen(ResetWhenWorkerStarts::EVENT, ResetWhenWorkerStarts::class);
        Event::listen(JobProcessing::class, ResetBeforeJob::class);
    }

    /**
     * Register the config publishing tag and the console commands.
     *
     * @return void
     */
    protected function registerConsole(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__ . '/../config/iam.php' => config_path('iam.php'),
        ], 'iam-config');

        $this->commands([InstallCommand::class, CheckCommand::class]);
    }

    /**
     * Register the contributor while its capability is on and namespace free.
     *
     * @param  bool  $on
     * @param  string  $namespace
     * @param  class-string<\SineMacula\Laravel\Authentication\Contracts\AuthenticationContextContributor>  $contributor
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function registerContributor(bool $on, string $namespace, string $contributor): void
    {
        if (!$on) {
            return;
        }

        $contributors = $this->app->make(ContextContributors::class);

        if (array_key_exists($namespace, $contributors->registered())) {
            return;
        }

        $contributors->register($namespace, $contributor);
    }

    /**
     * Bind every capability's adapters and the grant scope port.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function bindSeams(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app    = $this->app;
        $config = $app->make(ConfigRepository::class);

        $this->ssoOn           = SsoSeams::isOn($config);
        $this->mfaOn           = MfaSeams::isOn($config);
        $this->authorizationOn = AuthorizationSeams::isOn($config);

        foreach (self::seamProviders() as $provider) {
            foreach ($app->make($provider)->seams($config) as $binding) {
                $binding->apply($app);
            }
        }

        if ($this->authorizationOn) {
            $app->bindIf(GrantScope::class, GrantScopeAdapter::class);
        } else {
            $app->singletonIf(GrantScope::class, UnknownGrantScope::class);
        }
    }

    /**
     * Bind the seams and check storage once, and again once the app has booted.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException
     */
    private function settle(): void
    {
        if ($this->settled) {
            return;
        }

        $this->bindSeams();
        $this->checkStorage(false);

        $this->settled = true;

        $this->app->booted(function (): void {

            $this->checkStorage(true);
        });
    }

    /**
     * Align the storage keys; refuse a mismatch or, once booted, a lost member.
     *
     * @param  bool  $booted
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException
     */
    private function checkStorage(bool $booted): void
    {
        $app       = $this->app;
        $config    = $app->make(ConfigRepository::class);
        $alignment = $app->make(ConnectionAlignment::class);

        $this->written = array_replace($this->written, $this->alignStorage($alignment, $config, $app));

        if (self::isRunningUncheckedCommand($app)) {
            return;
        }

        if ($booted) {
            $alignment->assertRegistered($app);
        }

        $alignment->assertAligned($config, $app);
    }

    /**
     * Align the member keys; an unchecked command leaves an invalid key alone.
     *
     * @param  \SineMacula\Laravel\Iam\Storage\ConnectionAlignment  $alignment
     * @param  \Illuminate\Config\Repository  $config
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return array<string, ?string>
     *
     * @throws \InvalidArgumentException
     */
    private function alignStorage(ConnectionAlignment $alignment, ConfigRepository $config, Application $app): array
    {
        try {
            return $alignment->align($config, $this->written, $app);
        } catch (\InvalidArgumentException $exception) {

            if (!self::isRunningUncheckedCommand($this->app)) {
                throw $exception;
            }

            return [];
        }
    }

    /**
     * Whether the worker reset is on; only a clear off value turns it off.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isWorkerResetOn(mixed $value): bool
    {
        return $value === null || $value === '' || (filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? true);
    }

    /**
     * Whether the running console command skips the storage check.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return bool
     */
    private static function isRunningUncheckedCommand(Application $app): bool
    {
        return $app->runningInConsole() && in_array(self::commandName(), self::UNCHECKED_COMMANDS, true);
    }

    /**
     * The console command argv names; `list` for a bare `artisan`, else null.
     *
     * Options are skipped, with the value `--env` takes after a space.
     *
     * @return ?string
     */
    private static function commandName(): ?string
    {
        /** @var list<string> $arguments */
        $arguments = $_SERVER['argv'] ?? [];
        $value     = false;

        foreach (array_slice($arguments, 1) as $argument) {

            if (str_starts_with($argument, '-')) {
                $value = $argument === self::ENVIRONMENT_OPTION;

                continue;
            }

            if ($value) {
                $value = false;

                continue;
            }

            return $argument;
        }

        return basename($arguments[0] ?? '') === self::ARTISAN ? self::DEFAULT_COMMAND : null;
    }
}
