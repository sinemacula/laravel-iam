<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Iam\Audit\AuditRegistrations;
use SineMacula\Laravel\Iam\Audit\CarryCallerIntoJobs;
use SineMacula\Laravel\Iam\Audit\DeferredRefusals;
use SineMacula\Laravel\Iam\Audit\JobCallers;
use SineMacula\Laravel\Iam\Audit\OperationalAlerts;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextKeys;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\InsufficientAuthenticationMapping;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Checks\SsoCheckRegistration;
use SineMacula\Laravel\Iam\Console\CheckCommand;
use SineMacula\Laravel\Iam\Console\InstallCommand;
use SineMacula\Laravel\Iam\Delivery\DeliverySeams;
use SineMacula\Laravel\Iam\Mfa\ContextSeams;
use SineMacula\Laravel\Iam\Mfa\FactorCodeCallers;
use SineMacula\Laravel\Iam\Mfa\MfaContextContributor;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\PasskeySeams;
use SineMacula\Laravel\Iam\Provisioning\ProvisionOnUnlinkedResult;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Iam\Sso\LinkCallers;
use SineMacula\Laravel\Iam\Sso\RenewalRecorder;
use SineMacula\Laravel\Iam\Sso\SsoContextContributor;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Storage\ConnectionAlignment;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Iam\Tenancy\UnknownGrantScope;
use SineMacula\Laravel\Iam\Transactions\AfterConnectionCommits;
use SineMacula\Laravel\Iam\Transactions\CommittedWork;
use SineMacula\Laravel\Iam\Transactions\OutermostCommits;
use SineMacula\Laravel\Iam\Workers\ResetBeforeJob;
use SineMacula\Laravel\Iam\Workers\ResetBetweenRequests;
use SineMacula\Laravel\Iam\Workers\ResetWhenWorkerStarts;
use SineMacula\Laravel\Mfa\Context\AuthenticationContextContributor as MfaContributor;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;

/**
 * Package service provider: registers the package's configuration, the `iam`
 * manager, the callers MFA's challenge gateway keeps for its factor codes, the
 * records SSO's redemptions keep for one request, the callers queued jobs
 * carried, the grant half of SSO's principal scope, the storage connection's
 * alignment, the seam bindings, this package's checks of SSO's side with SSO's
 * own, the authentication context's keys on `laravel-authorization`'s key
 * catalogue, the storage check's booting and booted callbacks, the audit
 * trail's mappers and codes, the `mfa` and `sso` authentication context
 * contributors, the rendering of `laravel-authorization`'s
 * insufficient-authentication exception as MFA's step-up, the listeners
 * counting outermost commits and releasing the work held for a commit to
 * finish, the listener provisioning SSO's unlinked results, the listeners
 * handing the operational events to the application's alerting, the listeners
 * carrying the caller into each queued job, the worker reset listeners, the
 * publishing tag and the `iam:install` and `iam:check` commands.
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
 * Two more steps wait for the booting phase, from a `booting()` callback that
 * runs once every provider has registered and before any boots. The first is
 * SSO's seams answered from the application's memberships and tenant tree,
 * whose switches read whether the application has bound either, which it does
 * in its own provider's `register()`, after the packages': the rule is applied
 * to them once more there, over the very bindings of SSO's defaults it reserved
 * in `register()` only, so an application's binding of one of them made in
 * between is kept. The second is the storage connection. A member key can be
 * written only once its member has merged its configuration, which a member
 * registering after this package does only then, since a key written before
 * would replace the member's whole `storage` block; and an application provider
 * registered later may name another shared connection. So the member keys are
 * aligned again and checked there, before any provider boots. A provider
 * registered once the booting callbacks have run settles from its own `boot()`,
 * which Laravel runs for it at once.
 *
 * The storage step runs once more when the application has booted, from a
 * `booted()` callback the settling queues, because a provider's `boot()` can
 * still change what the booting phase settled: it can register a member, which
 * merges its configuration only then, or name another shared connection, or
 * point a member key elsewhere. Once booted, a member whose provider has still
 * not registered refuses boot (every member is required, IAM-1.3), since its
 * key could never be aligned; one registered later would read a connection this
 * package never checked.
 *
 * A storage connection mismatch, a member that has not registered, or a
 * connection key that is not a name, refuses boot, except while one of the
 * console commands that list, describe, discover, cache or clear configuration
 * runs, so the problem (a cached one included) can still be inspected and
 * cleared, as `laravel-mfa` skips its own boot check for them, or `iam:check`,
 * which reports it (`Checks\StorageCheck`) rather than stop before it can. The
 * command is read from the process's arguments; a process that names none runs
 * `list` only when it is Artisan, so any other script started without a command
 * (a test runner, a long-lived worker) is checked.
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
        CheckCommand::NAME,
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

    /** @var bool Whether the SSO capability's switch was on when the binding rule read it, which the `sso` contributor's registration follows. */
    private bool $ssoOn = false;

    /** @var bool Whether the MFA capability's switch was on when the binding rule read it, which the `mfa` contributor's registration and the step-up's rendering follow. */
    private bool $mfaOn = false;

    /** @var bool Whether the authorization capability's switch was on when the binding rule read it, which the step-up's rendering follows with the MFA capability's. */
    private bool $authorizationOn = false;

    /**
     * Register the configuration, the manager, the request's records, the
     * frames of the queued jobs running and the grant half of SSO's principal
     * scope, write the shared storage connection into every member key that is
     * unset and whose member has registered, apply the binding rule to every
     * seam binding, register this package's checks of SSO's side with SSO's own
     * and the declaration of the authentication context's keys on
     * `laravel-authorization`'s key catalogue, and register the callback that
     * aligns and checks the storage connections once every provider has
     * registered.
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
        $this->registerFactorCodeCallers();
        $this->registerRedemptionRecords();

        // The frames of the queued jobs running are frame state, as audit-log's
        // own job frames are: scoped, so the queue worker and Octane forget
        // them between jobs and requests, but outside this package's key for
        // scoped adapters, so the explicit reset a job calls between its own
        // units of work keeps the caller it carried (IAM-9.7)
        $this->app->scoped(JobCallers::class, static fn (): JobCallers => new JobCallers);

        $this->written = $this->alignStorage($this->app->make(ConnectionAlignment::class), $this->app->make(ConfigRepository::class), $this->app);

        $this->registerSeams();
        SsoCheckRegistration::register($this->app);
        AuthenticationContextKeys::register($this->app);
        $this->registerStorageCheck();
    }

    /**
     * Settle the storage connections if the booting phase passed before this
     * provider registered (it was registered while the application booted, or
     * after), register this package's part of the audit trail with audit-log
     * before it stops taking registrations (an audit-log that never registers
     * is not refused while a configuration command runs, as a member is not),
     * then queue the `mfa` and `sso` authentication context contributors'
     * registration for when every provider has booted, and bootstrap the
     * listeners counting outermost commits and releasing the work held for a
     * commit to finish, the listener provisioning SSO's unlinked results, the
     * listeners handing the operational events to the application's alerting,
     * the listeners carrying the caller into each queued job, the rendering of
     * `laravel-authorization`'s insufficient-authentication exception as MFA's
     * step-up, the worker reset listeners, the publishing tag and the console
     * commands.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function boot(): void
    {
        $this->settle();
        AuditRegistrations::register($this->app, !self::isRunningUncheckedCommand($this->app));
        $this->registerContextContributors();
        $this->registerCommitListeners();
        ProvisionOnUnlinkedResult::listen();
        OperationalAlerts::listen();
        CarryCallerIntoJobs::listen($this->app);
        InsufficientAuthenticationMapping::register($this->app, $this->authorizationOn && $this->mfaOn);
        $this->registerListeners();
        $this->registerConsole();
    }

    /**
     * Return the capabilities whose seam bindings the binding rule applies,
     * which `iam:check` reads the mandatory seams from too; each later
     * milestone adds its capability's `*Seams` class here.
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
            DeliverySeams::class,
            SsoSeams::class,
            TenancySeams::class,
            AuthorizationSeams::class,
        ];
    }

    /**
     * Register the `iam` manager singleton behind the facade, which resolves
     * every service from the application current when it is called.
     *
     * @return void
     */
    protected function registerManager(): void
    {
        $this->app->singleton('iam', static fn (): IamManager => new IamManager);
        $this->app->alias('iam', IamManager::class);
    }

    /**
     * Register the callers MFA's challenge gateway keeps beside the factor code
     * bindings it hands `laravel-authentication`, scoped, so they are one
     * request's or one job's alone (IAM-8.1): scoped under this package's own
     * key for its scoped adapters, which `Iam::resetWorkerState()` forgets as
     * it forgets every other one, and resolved through that key, so the
     * explicit reset never leaves a caller held for a binding something still
     * references.
     *
     * @return void
     */
    protected function registerFactorCodeCallers(): void
    {
        $key = BindingRule::SCOPED_PREFIX . FactorCodeCallers::class;

        $this->app->scoped($key, static fn (): FactorCodeCallers => new FactorCodeCallers);
        $this->app->bind(FactorCodeCallers::class, static fn (Application $app): mixed => $app->make($key));
    }

    /**
     * Register the records SSO's redemptions keep for one request: the
     * redemption admitted, which `laravel-authentication`'s external identity
     * links contract answers from, the renewal a re-authentication records
     * before its one write, the refusals `laravel-authentication` reports
     * inside a transaction, held for the audit trail until the outermost one
     * has ended, the outermost commits each connection has begun, which a
     * standalone `link` reads to tell whether its attempt reached its commit
     * before it failed, and the caller of the `link` redemption running, whose
     * session SSO's freshness contract judges, and the work held until a
     * connection's commit has finished. Each is scoped, so it is one request's
     * or one job's alone (IAM-8.1), under this package's own key for its scoped
     * adapters, which `Iam::resetWorkerState()` forgets as it forgets every
     * other one, and resolved through that key, so the explicit reset never
     * leaves a record held where something still resolves it.
     *
     * @return void
     */
    protected function registerRedemptionRecords(): void
    {
        foreach ([AdmittedRedemptions::class, RenewalRecorder::class, DeferredRefusals::class, OutermostCommits::class, LinkCallers::class, CommittedWork::class] as $record) {

            $key = BindingRule::SCOPED_PREFIX . $record;

            $this->app->scoped($key, static fn (): object => new $record);
            $this->app->bind($record, static fn (Application $app): mixed => $app->make($key));
        }
    }

    /**
     * Register this package's contributors of the `mfa` and `sso` namespaces
     * with `laravel-authentication`'s authentication context, each once, while
     * its capability's switch is on (IAM-3.12, IAM-4.8), as the binding rule
     * read it when this package registered, so each contributor and its
     * capability's adapters are bound together or not at all, whatever a later
     * provider writes to the switch, from a `booted()` callback, which runs
     * once every provider has booted (at once when the application already
     * has). `laravel-authentication` asks for a registration from `boot()`, and
     * a member may be registered from another provider's `boot()`, after this
     * package's has run: its provider binds its contributors only then, so a
     * registration made from this package's `boot()` would go to an instance
     * nobody keeps and be lost without a word. A contributor the application
     * registered under either namespace before the application finished
     * booting, from any provider's `boot()`, is kept, as an application's
     * binding of a seam is (IAM-8.4); one it registers once the application has
     * booted is `laravel-authentication`'s `LogicException`, since a namespace
     * is taken once.
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
     * Apply the binding rule to every capability's seam bindings, and keep its
     * outcome for the checks, and whether the MFA, SSO and authorization
     * capabilities' switches were on for the `mfa` and `sso` contributors'
     * registration and the step-up's rendering; and bind the default of this
     * package's own port for the grant half of SSO's principal scope (IAM-6.8),
     * only while nothing is bound to it, so an application's or a test's
     * binding, made before or after, is kept: this package does not answer it
     * from `laravel-authorization`'s grant scope query (AUTHZ-14.2) yet, so it
     * is `UnknownGrantScope`, which answers `unknown` for everyone (Q9),
     * shared, since it reads and keeps nothing. It is no member's seam, so the
     * binding rule has no default of a member's to tell it from.
     *
     * While the SSO capability's switch is on, the seams answered from the
     * application's memberships and tenant tree that the rule left off are
     * reserved for the rule applied again once every provider has registered
     * (`BindingRule::reserve()`): the exact binding of SSO's default each holds
     * is recorded, SSO's default bound there first where SSO has not registered
     * yet, as SSO would bind it, so that only a seam still holding it then is
     * bound over, and any binding the application makes over it meanwhile is
     * kept.
     *
     * The rule reads the bindings and their switches from the configuration
     * every member will hold once registered, whichever of them has not
     * registered yet, so every provider order, and a cached configuration, bind
     * the same. The switch is this package's own, merged before the rule runs,
     * so it reads the same here as the rule reads it: a value a later provider
     * writes comes too late for either.
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

        $rule    = $app->make(BindingRule::class);
        $outcome = $rule->apply($app, ...$capabilities);
        $config  = $app->make(ConfigRepository::class);

        $this->ssoOn           = SsoSeams::isOn($config);
        $this->mfaOn           = MfaSeams::isOn($config);
        $this->authorizationOn = AuthorizationSeams::isOn($config);

        if ($this->ssoOn) {
            $outcome = $rule->reserve($app, $outcome, $app->make(TenancySeams::class));
        }

        $app->instance(BindingOutcome::class, $outcome);
        $app->singletonIf(GrantScope::class, UnknownGrantScope::class);
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
     * Count every outermost commit a connection begins, in this request's or
     * this job's record (`OutermostCommits`), release the work held until a
     * connection's commit has finished, every callback queued on it run
     * (`AfterConnectionCommits::committed()`), and release what a commit left
     * held, a commit callback having failed, as the request, the console
     * command or the queued job ends (`AfterConnectionCommits::settle()`). Each
     * listener resolves what it calls from the application current when it
     * runs, never from the events dispatcher's container: under Octane that is
     * the worker's own application, while the request's records are its
     * sandbox's. All are always on, whatever the worker reset's switch: a
     * standalone `link` is never run again once its attempt has reached its
     * commit, and an enforcement change's or a reported policy change's second
     * pass waits for the change to commit.
     *
     * @return void
     */
    protected function registerCommitListeners(): void
    {
        Event::listen(TransactionCommitting::class, static function (TransactionCommitting $event): void {

            Container::getInstance()->make(OutermostCommits::class)->committing($event);
        });

        Event::listen(TransactionCommitted::class, static function (TransactionCommitted $event): void {

            Container::getInstance()->make(AfterConnectionCommits::class)->committed($event);
        });

        Event::listen([JobProcessed::class, JobExceptionOccurred::class], static function (): void {

            self::settleHeldWork();
        });

        $this->app->terminating(static function (): void {

            self::settleHeldWork();
        });
    }

    /**
     * Register the package's config publishing tag and its console commands,
     * `iam:install` and `iam:check`, in the console only.
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
     * Register this package's contributor under the namespace while its
     * capability's switch was on when the binding rule read it and nothing else
     * holds the namespace.
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
     * Apply the binding rule once more to the seams answered from the
     * application's memberships and tenant tree, then align the storage
     * connections again and refuse a mismatch, once only, whichever phase
     * reaches it first, and queue the same once more for when the application
     * has booted, refusing then a member that has still not registered.
     *
     * The seams answered from the memberships and the tree are applied again
     * only while the SSO capability's switch was on when the binding rule first
     * read it, and follow the switch as it read then, whatever a provider
     * registering later wrote, so they and SSO's other seams are bound together
     * or not at all: a membership contract or a tree the application binds in
     * its own provider's `register()`, which Laravel runs after the packages',
     * is bound only by now, and binds the adapters it answers over the very
     * bindings of SSO's defaults reserved as the rule first ran, never over a
     * binding of SSO's seam the application has made meanwhile, even one of
     * SSO's own default class. The outcome kept for the checks gains whatever
     * this binds or keeps.
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
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException
     */
    private function settle(): void
    {
        if ($this->settled) {
            return;
        }

        if ($this->ssoOn) {
            $tenancy = $this->app->make(TenancySeams::class, ['ssoOn' => $this->ssoOn]);
            $outcome = $this->app->make(BindingRule::class)->applyAgain($this->app, $this->app->make(BindingOutcome::class), $tenancy);

            $this->app->instance(BindingOutcome::class, $outcome);
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
     * Release the work a commit left held, as a unit of work ends, through the
     * application current then.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function settleHeldWork(): void
    {
        Container::getInstance()->make(AfterConnectionCommits::class)->settle();
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
}
