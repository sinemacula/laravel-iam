<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Storage\ConnectionAlignment;
use SineMacula\Laravel\Iam\Workers\ResetBeforeJob;
use SineMacula\Laravel\Iam\Workers\ResetBetweenRequests;
use SineMacula\Laravel\Iam\Workers\ResetWhenWorkerStarts;
use Symfony\Component\Console\Input\ArgvInput;

/**
 * Package service provider: registers the package's configuration, the `iam`
 * manager, the storage connection's alignment, the binding rule's booting
 * callback, the worker reset listeners and the publishing tag.
 *
 * Everything this package binds over a member's seam is bound once, from one
 * `booting()` callback: after every service provider has registered, so a
 * member that binds its defaults with a plain `bind()` has done so whatever
 * order the providers register in, and before any provider boots. A seam is
 * bound only where it is unbound or still bound to the member's own default, so
 * an application binding made in any `register()` is kept and one made in a
 * `boot()` replaces the adapter (IAM-8.4). A provider registered while the
 * application boots, once the booting callbacks have run, or after it has
 * booted applies the same rule from its own `boot()`, which Laravel runs for it
 * at once; only the providers that boot after it can still replace an adapter.
 *
 * A storage connection mismatch, or a connection key that is not a name,
 * refuses boot, except while one of the console commands that list, describe,
 * discover, cache or clear configuration runs, so the problem (a cached one
 * included) can still be inspected and cleared, as `laravel-mfa` skips its own
 * boot check for them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class IamServiceProvider extends ServiceProvider
{
    /** @var list<string> The console commands a storage connection mismatch does not refuse. */
    private const array UNCHECKED_COMMANDS = [
        'config:cache',
        'config:clear',
        'config:show',
        'help',
        'list',
        'optimize:clear',
        'package:discover',
    ];

    /** @var array<string, ?string> The member keys this provider wrote as it registered, with what it wrote. */
    private array $written = [];

    /** @var bool Whether the storage connections and the seam bindings have been settled. */
    private bool $settled = false;

    /**
     * Register the configuration and the manager, write the shared storage
     * connection into every member key that is unset and whose member has
     * registered, and register the callback that checks the storage connections
     * and applies the binding rule once every provider has registered.
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

        $this->written = $this->alignStorage($this->app->make(ConnectionAlignment::class), $this->app->make(ConfigRepository::class), $this->app);

        $this->registerBindingRule();
    }

    /**
     * Settle the storage connections and the seam bindings if the booting phase
     * passed before this provider registered (it was registered while the
     * application booted, or after), then bootstrap the worker reset listeners
     * and the publishing tag.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function boot(): void
    {
        $this->settle();
        $this->registerListeners();
        $this->registerPublishing();
    }

    /**
     * Register the `iam` manager singleton behind the facade.
     *
     * @return void
     */
    protected function registerManager(): void
    {
        $this->app->singleton('iam', static fn (Application $app): IamManager => new IamManager($app));
        $this->app->alias('iam', IamManager::class);
    }

    /**
     * Register the callback that settles the storage connections and the seam
     * bindings in the booting phase. When the application has already booted,
     * the callback would never run, and none is registered: Laravel boots a
     * provider registered then at once, and `boot()` settles.
     *
     * @return void
     */
    protected function registerBindingRule(): void
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
     * Register the reset of every member's request state before each Octane
     * request and once as each Octane worker starts, by the events' names so
     * Octane stays optional, and before each queued job, unless the application
     * turned it off.
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
        Event::listen(ResetBetweenRequests::EVENT, ResetBetweenRequests::class);
        Event::listen(JobProcessing::class, ResetBeforeJob::class);
    }

    /**
     * Register the package's config publishing tag.
     *
     * @return void
     */
    protected function registerPublishing(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__ . '/../config/iam.php' => config_path('iam.php'),
        ], 'iam-config');
    }

    /**
     * Align the storage connections, refuse a mismatch, and apply every seam
     * binding the binding rule allows, keeping its outcome for the checks;
     * once only, whichever phase reaches it first.
     *
     * The alignment runs again here because a member that registers after this
     * package merges its configuration only then, and the application may have
     * changed the shared connection since this package registered; every member
     * has registered by now.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException
     */
    private function settle(): void
    {
        if ($this->settled) {
            return;
        }

        $app       = $this->app;
        $config    = $app->make(ConfigRepository::class);
        $alignment = $app->make(ConnectionAlignment::class);

        $this->alignStorage($alignment, $config);

        if (!self::isRunningUncheckedCommand($app)) {
            $alignment->assertAligned($config);
        }

        $bindings = array_merge(...array_map(static fn (string $provider): array => $app->make($provider)->seams($config), self::seamProviders()));

        $app->instance(BindingOutcome::class, $app->make(BindingRule::class)->apply($app, ...$bindings));

        $this->settled = true;
    }

    /**
     * Write the shared connection into every member key the alignment allows,
     * and return what was written. While a console command that lists,
     * describes, discovers, caches or clears configuration runs, a connection
     * key that is not a name is left as it is, and nothing more is aligned, so
     * the command can still clear or replace it; anywhere else it fails closed.
     *
     * @param  \SineMacula\Laravel\Iam\Storage\ConnectionAlignment  $alignment
     * @param  \Illuminate\Config\Repository  $config
     * @param  ?\Illuminate\Contracts\Foundation\Application  $registering
     * @return array<string, ?string>
     *
     * @throws \InvalidArgumentException
     */
    private function alignStorage(ConnectionAlignment $alignment, ConfigRepository $config, ?Application $registering = null): array
    {
        try {
            return $alignment->align($config, $this->written, $registering);
        } catch (\InvalidArgumentException $exception) {

            if (!self::isRunningUncheckedCommand($this->app)) {
                throw $exception;
            }

            return [];
        }
    }

    /**
     * Whether the worker reset's switch leaves the reset on, read leniently, as
     * the members read a switch an environment variable fills: `false`, as a
     * boolean or as text, `0`, `off` and `no` turn it off. Anything else leaves
     * it on: `true`, `1`, `on` and `yes`, and a missing, empty or unrecognised
     * value, since a reset that runs needlessly costs nothing, while one
     * skipped lets a request's state reach the next, and refusing the value
     * would stop every command, the ones that clear a cached configuration
     * among them.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isWorkerResetOn(mixed $value): bool
    {
        return $value === null || $value === '' || (filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? true);
    }

    /**
     * Whether the console command running is one a storage connection mismatch
     * does not refuse, found as the console finds it: the first argument that
     * is not an option, so `artisan -v config:clear` is `config:clear` too.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return bool
     */
    private static function isRunningUncheckedCommand(Application $app): bool
    {
        return $app->runningInConsole() && in_array((new ArgvInput)->getFirstArgument(), self::UNCHECKED_COMMANDS, true);
    }

    /**
     * Return the capabilities whose seam bindings the binding rule applies;
     * each later milestone adds its capability's `*Seams` class here.
     *
     * @return list<class-string<\SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams>>
     */
    private static function seamProviders(): array
    {
        return [];
    }
}
