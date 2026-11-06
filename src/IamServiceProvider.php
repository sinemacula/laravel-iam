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
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Delivery\DeliverySeams;
use SineMacula\Laravel\Iam\Mfa\ContextSeams;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\PasskeySeams;
use SineMacula\Laravel\Iam\Storage\ConnectionAlignment;
use SineMacula\Laravel\Iam\Workers\ResetBeforeJob;
use SineMacula\Laravel\Iam\Workers\ResetBetweenRequests;
use SineMacula\Laravel\Iam\Workers\ResetWhenWorkerStarts;

/**
 * Package service provider: registers the package's configuration, the `iam`
 * manager, the storage connection's alignment, the seam bindings, the storage
 * check's booting and booted callbacks, the worker reset listeners and the
 * publishing tag.
 *
 * Everything this package binds over a member's seam is bound once, in
 * `register()`, where the seam is unbound or still bound to the member's own
 * default (IAM-8.4). Every member binds its defaults only where nothing is
 * bound yet, so a member registering after this package keeps the adapter, and
 * one registered before it is recognised as the member's default and replaced;
 * an application binding made in a `register()` before this package's is kept,
 * and one made in a later `register()` or in any `boot()` replaces the adapter.
 * The bindings' switches are read with every member's packaged configuration
 * beneath the application's, so a member that has not merged its configuration
 * yet switches them as it will once it has.
 *
 * One step still waits for the booting phase, from a `booting()` callback that
 * runs once every provider has registered and before any boots: the storage
 * connection. It is not there for any member's bindings. A member key can be
 * written only once its member has merged its configuration, which a member
 * registering after this package does only then, since a key written before
 * would replace the member's whole `storage` block; and an application provider
 * registered later may name another shared connection. So the member keys are
 * aligned again and checked there, before any provider boots. A provider
 * registered once the booting callbacks have run settles from its own `boot()`,
 * which Laravel runs for it at once.
 *
 * The step runs once more when the application has booted, from a `booted()`
 * callback the settling queues, because a provider's `boot()` can still change
 * what the booting phase settled: it can register a member, which merges its
 * configuration only then, or name another shared connection, or point a member
 * key elsewhere. Once booted, a member whose provider has still not registered
 * refuses boot (every member is required, IAM-1.3), since its key could never
 * be aligned; one registered later would read a connection this package never
 * checked.
 *
 * A storage connection mismatch, a member that has not registered, or a
 * connection key that is not a name, refuses boot, except while one of the
 * console commands that list, describe, discover, cache or clear configuration
 * runs, so the problem (a cached one included) can still be inspected and
 * cleared, as `laravel-mfa` skips its own boot check for them. The command is
 * read from the process's arguments; a process that names none runs `list` only
 * when it is Artisan, so any other script started without a command (a test
 * runner, a long-lived worker) is checked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class IamServiceProvider extends ServiceProvider
{
    /** @var list<string> The console commands neither a storage connection mismatch nor a missing member refuses. */
    private const array UNCHECKED_COMMANDS = [
        'config:cache',
        'config:clear',
        'config:show',
        'help',
        'list',
        'optimize:clear',
        'package:discover',
    ];

    /** @var string The console command Artisan runs when the process's arguments name none. */
    private const string DEFAULT_COMMAND = 'list';

    /** @var string The script whose process runs the default command when its arguments name none. */
    private const string ARTISAN = 'artisan';

    /** @var string The console's only global option that takes a value, which may follow it after a space. */
    private const string ENVIRONMENT_OPTION = '--env';

    /** @var array<string, ?string> The member keys this provider wrote, as it registered and as it settled, with what it wrote last. */
    private array $written = [];

    /** @var bool Whether the storage connections have been settled, and their check once the application has booted queued. */
    private bool $settled = false;

    /**
     * Register the configuration and the manager, write the shared storage
     * connection into every member key that is unset and whose member has
     * registered, apply the binding rule to every seam binding, and register
     * the callback that aligns and checks the storage connections once every
     * provider has registered.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/iam.php', 'iam');

        $this->registerManager();

        $this->written = $this->alignStorage($this->app->make(ConnectionAlignment::class), $this->app->make(ConfigRepository::class), $this->app);

        $this->registerSeams();
        $this->registerStorageCheck();
    }

    /**
     * Settle the storage connections if the booting phase passed before this
     * provider registered (it was registered while the application booted, or
     * after), then bootstrap the worker reset listeners and the publishing tag.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException
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
     * Apply the binding rule to every capability's seam bindings, and keep its
     * outcome for the checks.
     *
     * The rule reads the bindings and their switches from the configuration
     * every member will hold once registered, whichever of them has not
     * registered yet, so every provider order, and a cached configuration, bind
     * the same.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    protected function registerSeams(): void
    {
        $app          = $this->app;
        $capabilities = array_map(static fn (string $provider): ProvidesSeams => $app->make($provider), self::seamProviders());

        $app->instance(BindingOutcome::class, $app->make(BindingRule::class)->apply($app, ...$capabilities));
    }

    /**
     * Register the callback that settles the storage connections in the booting
     * phase. When the application has already booted, the callback would never
     * run, and none is registered: Laravel boots a provider registered then at
     * once, and `boot()` settles.
     *
     * @return void
     */
    protected function registerStorageCheck(): void
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
     * Align the storage connections again and refuse a mismatch, once only,
     * whichever phase reaches it first, and queue the same once more for when
     * the application has booted, refusing then a member that has still not
     * registered.
     *
     * Neither can be done in `register()` alone: a member that registers after
     * this package merges its configuration only then, so its key can be
     * neither written nor checked before, and an application provider that
     * registers later may name another shared connection. Every member the
     * application registers with the other providers has registered by now; one
     * a provider registers from its `boot()` has not, and is left, as is its
     * key, for the callback that runs once the application has booted. A
     * callback queued once the application has booted runs at once.
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

        $this->checkStorage(false);

        $this->settled = true;

        $this->app->booted(function (): void {

            $this->checkStorage(true);
        });
    }

    /**
     * Write the shared connection into every member key whose member has
     * registered, refuse a key naming another connection, and, once the
     * application has booted, refuse a member that has not registered; none is
     * refused while a configuration command runs.
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
     * Write the shared connection into every member key the alignment allows,
     * leaving a member whose provider has not registered yet, and return what
     * was written. While a console command that lists, describes, discovers,
     * caches or clears configuration runs, a connection key that is not a name
     * is left as it is, and nothing more is aligned, so the command can still
     * clear or replace it; anywhere else it fails closed.
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
     * does not refuse.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return bool
     */
    private static function isRunningUncheckedCommand(Application $app): bool
    {
        return $app->runningInConsole() && in_array(self::commandName(), self::UNCHECKED_COMMANDS, true);
    }

    /**
     * Return the console command the process's arguments name, found as the
     * console finds it: the first argument that is neither an option nor the
     * value of `--env` given after a space, the only global option that takes a
     * value (so `artisan -v config:clear` and `artisan --env production
     * config:clear` are both `config:clear`).
     *
     * When there is none, the command is `list`, the console's default, only
     * when the process is Artisan (a bare `artisan`, or `artisan -v`); any
     * other process that names no command (a test runner given only options, a
     * long-lived worker script) runs no console command at all, and `null` is
     * returned, so it is checked, as `laravel-mfa`'s own boot check, which
     * reads the first argument, checks it.
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

    /**
     * Return the capabilities whose seam bindings the binding rule applies;
     * each later milestone adds its capability's `*Seams` class here.
     *
     * @return list<class-string<\SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams>>
     */
    private static function seamProviders(): array
    {
        return [
            MfaSeams::class,
            PasskeySeams::class,
            ContextSeams::class,
            DeliverySeams::class,
        ];
    }
}
