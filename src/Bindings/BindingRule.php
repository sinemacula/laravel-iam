<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container as IlluminateContainer;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use Illuminate\Filesystem\Filesystem;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Binds this package's adapters over the members' seams without ever replacing
 * the application's binding (IAM-8.4).
 *
 * It runs once, as this package's service provider registers. Each binding
 * whose switch is on is applied with its declared lifetime where the seam is
 * unbound or still bound to the member's own default; anything else is the
 * application's binding, made before this package registered, and is kept.
 * Every member binds its defaults only where nothing is bound yet, so a member
 * that registers later keeps the adapter, while a binding the application makes
 * in a later `register()` or in a `boot()` replaces it. A provider that binds
 * over a seam unconditionally (`bind()`, `singleton()`) after this package
 * registers replaces the adapter too, member or not.
 *
 * A binding whose switch reads what the application binds, not only its
 * configuration (SSO's seams answered from the application's memberships and
 * tenant tree), is applied once more once every provider has registered
 * (`applyAgain()`), from this package's booting callback, where it was off when
 * this package registered: Laravel registers the application's own providers
 * after the packages', so a binding made in an application provider's
 * `register()` is there only then. Such a seam is reserved as the rule first
 * runs (`reserve()`): the exact binding of the member's default it holds then
 * is recorded, and where it is unbound, because the member registers later, the
 * member's default is bound there and then, shared, as the member would bind
 * it, so the member's own `*If()` binding leaves it. Applied again, the rule
 * binds the adapter only where the seam still holds exactly that binding;
 * anything bound over it meanwhile is the application's, and is kept, even a
 * binding of the member's own default class, which by its class alone could not
 * be told from the member's.
 *
 * A member that binds its defaults unconditionally, as `laravel-authorization`
 * does, replaces the adapter if it registers after this package; the seams it
 * replaced are bound again once every provider has registered (`reclaim()`),
 * from the same booting callback, where each still holds that member's default.
 * Its binding resolves a key of its own holding the class its configuration
 * names, so the seam is the member's only while that key holds the member's
 * default class too (`SeamBinding::$defaultKey`): a class the application names
 * there is its binding, and kept. An application's binding of such a seam the
 * rule kept as it ran is overwritten the same way, so the rule records what
 * binds it again (`BindingOutcome::$restorers`), and `reclaim()` binds it again
 * where that member's default holds the seam once more. `reclaim()` runs once
 * more when the application has booted, for such a member registered from
 * another provider's `boot()`. Such a member listens for some of its seams
 * being bound again only where the seam is unbound as it registers, so where
 * the rule binds first it registers the member's listener before the adapter
 * (`SeamBinding::$rebinding`), and the seam is listened for once, in every
 * provider order.
 *
 * A scoped adapter is never scoped under the member's seam itself: Laravel
 * keeps a scoped abstract on its list of scoped instances for good, and forgets
 * whatever instance is held under it between requests and jobs, so an instance
 * or a singleton the application bound over the seam later would be dropped,
 * and the adapter would resolve again from the next request or job on. The
 * adapter is scoped under a key this package owns instead, and the seam
 * resolves that key through a transient binding, as `laravel-authorization`
 * scopes its own defaults. For the same reason a seam the rule binds over is
 * taken off that list first, whatever the adapter's lifetime: a member that
 * registered earlier and bound its default with `scopedIf()`, as `laravel-sso`
 * does, left the seam on it, and a binding over the seam leaves it there, so a
 * shared adapter would be built again for every request and job, and an
 * instance the application bound later would be dropped.
 *
 * The bindings and their switches are read from the configuration every member
 * will hold once it has registered, whatever order the providers register in: a
 * member that registers after this package merges its packaged configuration
 * only then, so a switch on a member's feature (`sso.features`, MFA's factor
 * types) would otherwise read nothing in one order and the member's value in
 * another, and the same application would bind differently with its
 * configuration cached and not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BindingRule
{
    /** @var string The prefix of the keys this package scopes its scoped adapters under, each followed by its seam. */
    public const string SCOPED_PREFIX = 'iam.scoped:';

    /** @var array<string, class-string<\Illuminate\Support\ServiceProvider>> The key each member merges its packaged configuration under, with the provider that merges it from its package's `config` directory. */
    private const array MEMBER_CONFIGURATION = [
        'authentication' => AuthenticationServiceProvider::class,
        'authorization'  => AuthorizationServiceProvider::class,
        'mfa'            => MfaServiceProvider::class,
        'sso'            => SsoServiceProvider::class,
        'audit-log'      => AuditLogServiceProvider::class,
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Bindings\MemberDefaults  $defaults
     */
    public function __construct(

        /** Tells a member's default binding from the application's. */
        private MemberDefaults $defaults,
    ) {}

    /**
     * Apply each capability's bindings the rule allows, and report what it
     * bound and what it kept. A binding whose switch is off is in neither list.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams  ...$capabilities
     * @return \SineMacula\Laravel\Iam\Bindings\BindingOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function apply(Application $app, ProvidesSeams ...$capabilities): BindingOutcome
    {
        $switches    = self::switches($app);
        $bindings    = self::bindingsOf($switches, $capabilities);
        $replaceable = fn (SeamBinding $binding): bool => $this->defaults->isReplaceable($app, $binding->abstract, $binding->memberDefaults, $binding->defaultKey);
        $outcome     = $this->applied($app, $switches, $bindings, new BindingOutcome([], []), $replaceable);
        $restorers   = $this->restorers($app, $bindings, $outcome);

        return $restorers === [] ? $outcome : new BindingOutcome($outcome->bound, $outcome->kept, $outcome->reserved, $restorers);
    }

    /**
     * Reserve the capabilities' bindings the outcome lists neither as bound nor
     * as kept, for the rule applied again once every provider has registered:
     * record, for each seam that is unbound or bound to the member's own
     * default, the exact binding it holds, having first bound the member's
     * default there, shared, where it is unbound, so the member, when it
     * registers later, keeps it with its `*If()` binding. A seam bound to
     * anything else is the application's, and is not reserved. Answer the
     * outcome with them added, the same outcome when there are none.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Iam\Bindings\BindingOutcome  $outcome
     * @param  \SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams  ...$capabilities
     * @return \SineMacula\Laravel\Iam\Bindings\BindingOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function reserve(Application $app, BindingOutcome $outcome, ProvidesSeams ...$capabilities): BindingOutcome
    {
        $reserved = $outcome->reserved;

        foreach (self::undecided(self::bindingsOf(self::switches($app), $capabilities), $outcome) as $binding) {

            $held = $this->reservation($app, $binding);

            if ($held === null) {
                continue;
            }

            $reserved[$binding->abstract] = $held;
        }

        return $reserved === $outcome->reserved ? $outcome : new BindingOutcome($outcome->bound, $outcome->kept, $reserved, $outcome->restorers);
    }

    /**
     * Apply the rule again to the capabilities' bindings the outcome lists
     * neither as bound nor as kept, once every provider has registered: a
     * binding whose switch reads the container (the application's memberships
     * or tenant tree, bound in an application provider's `register()`, which
     * Laravel runs after the packages') may turn on only then. Each whose
     * switch is on is bound where the seam still holds exactly the binding the
     * outcome reserved for it, the member's default, and kept otherwise: a seam
     * never reserved, or bound over since, is the application's. Answer the
     * outcome with them added, the same outcome when there are none.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Iam\Bindings\BindingOutcome  $outcome
     * @param  \SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams  ...$capabilities
     * @return \SineMacula\Laravel\Iam\Bindings\BindingOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function applyAgain(Application $app, BindingOutcome $outcome, ProvidesSeams ...$capabilities): BindingOutcome
    {
        $switches = self::switches($app);
        $bindings = self::undecided(self::bindingsOf($switches, $capabilities), $outcome);

        return $this->applied($app, $switches, $bindings, $outcome, fn (SeamBinding $binding): bool => $this->isStillReserved($app, $binding->abstract, $outcome));
    }

    /**
     * Bind the adapter again over each seam the outcome lists as bound that a
     * member has bound its own default over since, and the application's
     * binding again over each seam the outcome kept with it that the member has
     * bound its default over since, once every provider has registered, and
     * once more when the application has booted: a member that binds its
     * defaults unconditionally (`laravel-authorization`, with a plain `bind()`
     * over a scoped key of its own) and registers after this package replaces
     * the adapter, or the application's binding made before this package
     * registered, as it registers, whether with the other providers or from
     * another provider's `boot()`. A seam that holds the adapter or the
     * application's binding still, or anything but the member's default (the
     * application's binding, made since), is left as it is, so the
     * application's binding still wins. Only the bindings the rule decided as
     * it first ran are looked at, so each follows its switch as it read then,
     * and a kept seam is bound again only with the binding recorded as the rule
     * ran (`BindingOutcome::$restorers`). The outcome is not changed: every
     * seam bound again was bound or kept before. Answer the seams bound again.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Iam\Bindings\BindingOutcome  $outcome
     * @param  \SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams  ...$capabilities
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function reclaim(Application $app, BindingOutcome $outcome, ProvidesSeams ...$capabilities): array
    {
        $reclaimed = [];

        foreach (self::bindingsOf(self::switches($app), $capabilities) as $binding) {

            $restore = in_array($binding->abstract, $outcome->bound, true)
                ? fn (Application $app) => $this->bind($app, $binding)
                : $outcome->restorers[$binding->abstract] ?? null;

            if ($restore === null || !$this->defaults->holdsDefault($app, $binding->abstract, $binding->memberDefaults, $binding->defaultKey)) {
                continue;
            }

            $restore($app);

            $reclaimed[] = $binding->abstract;
        }

        return $reclaimed;
    }

    /**
     * What binds the application's binding again over each seam the outcome
     * kept with it whose member binds its defaults unconditionally (a binding
     * naming the key its default is held under, `SeamBinding::$defaultKey`), by
     * seam: that member, registering after this package, binds its default over
     * the application's binding.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>  $bindings
     * @param  \SineMacula\Laravel\Iam\Bindings\BindingOutcome  $outcome
     * @return array<class-string, \Closure(\Illuminate\Contracts\Container\Container): void>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function restorers(Application $app, array $bindings, BindingOutcome $outcome): array
    {
        $restorers = [];

        foreach ($bindings as $binding) {

            $restorer = $binding->defaultKey !== null && in_array($binding->abstract, $outcome->kept, true) ? $this->defaults->restorerOf($app, $binding->abstract) : null;

            if ($restorer === null) {
                continue;
            }

            $restorers[$binding->abstract] = $restorer;
        }

        return $restorers;
    }

    /**
     * The exact binding of the member's default the seam holds, once the
     * member's first default is bound there, shared, where it is unbound; or
     * `null` when the seam holds anything else, the binding has no member
     * default, or the container keeps no binding table to read.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Iam\Bindings\SeamBinding  $binding
     * @return ?\Closure(mixed...): mixed
     */
    private function reservation(Application $app, SeamBinding $binding): ?\Closure
    {
        $default = $binding->memberDefaults[0] ?? null;

        if ($default === null || !$this->defaults->isReplaceable($app, $binding->abstract, $binding->memberDefaults, $binding->defaultKey)) {
            return null;
        }

        if (!$app->bound($binding->abstract)) {
            $app->singleton($binding->abstract, $default);
        }

        return $this->defaults->bindingOf($app, $binding->abstract);
    }

    /**
     * The bindings given the outcome lists neither as bound nor as kept.
     *
     * @param  list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>  $bindings
     * @param  \SineMacula\Laravel\Iam\Bindings\BindingOutcome  $outcome
     * @return array<int, \SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    private static function undecided(array $bindings, BindingOutcome $outcome): array
    {
        $decided = [...$outcome->bound, ...$outcome->kept];

        return array_filter($bindings, static fn (SeamBinding $binding): bool => !in_array($binding->abstract, $decided, true));
    }

    /**
     * Whether the seam still holds exactly the binding the outcome reserved for
     * it: never when it reserved none.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  string  $abstract
     * @param  \SineMacula\Laravel\Iam\Bindings\BindingOutcome  $outcome
     * @return bool
     */
    private function isStillReserved(Application $app, string $abstract, BindingOutcome $outcome): bool
    {
        $reserved = $outcome->reserved[$abstract] ?? null;

        return $reserved !== null && $this->defaults->bindingOf($app, $abstract) === $reserved;
    }

    /**
     * Every binding the capabilities declare, in order.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $switches
     * @param  list<\SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams>  $capabilities
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    private static function bindingsOf(Repository $switches, array $capabilities): array
    {
        return array_merge(...array_map(static fn (ProvidesSeams $capability): array => $capability->seams($switches), $capabilities));
    }

    /**
     * Apply each binding whose switch is on, over the seam where the predicate
     * given says it may be replaced, and answer the outcome given with what was
     * bound and kept added: the outcome given itself when nothing was.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \Illuminate\Contracts\Config\Repository  $switches
     * @param  array<int, \SineMacula\Laravel\Iam\Bindings\SeamBinding>  $bindings
     * @param  \SineMacula\Laravel\Iam\Bindings\BindingOutcome  $outcome
     * @param  \Closure(\SineMacula\Laravel\Iam\Bindings\SeamBinding): bool  $replaceable
     * @return \SineMacula\Laravel\Iam\Bindings\BindingOutcome
     */
    private function applied(Application $app, Repository $switches, array $bindings, BindingOutcome $outcome, \Closure $replaceable): BindingOutcome
    {
        $bound = $outcome->bound;
        $kept  = $outcome->kept;

        foreach ($bindings as $binding) {

            if ($binding->appliesWhen !== null && !($binding->appliesWhen)($switches)) {
                continue;
            }

            if (!$replaceable($binding)) {
                $kept[] = $binding->abstract;

                continue;
            }

            $this->bind($app, $binding);

            $bound[] = $binding->abstract;
        }

        return $bound === $outcome->bound && $kept === $outcome->kept ? $outcome : new BindingOutcome($bound, $kept, $outcome->reserved, $outcome->restorers);
    }

    /**
     * Return the configuration the bindings and their switches are read from: a
     * copy of the application's, with the packaged configuration of each member
     * that has not registered yet merged beneath it one level deep, as the
     * member's `mergeConfigFrom()` will merge it, so the member reads as it
     * will once it has registered. The application's own values win. A member
     * that has registered has merged its configuration already, and the
     * application's configuration is never written.
     *
     * A cached configuration is read as it is: it already holds what every
     * member merged when it was cached, and Laravel merges nothing over it.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return \Illuminate\Contracts\Config\Repository
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private static function switches(Application $app): Repository
    {
        $config = $app->make(Repository::class);

        if (self::isConfigurationCached($app)) {
            return $config;
        }

        $switches = new ConfigRepository($config->all());

        foreach (self::MEMBER_CONFIGURATION as $key => $provider) {

            if ($app->getProviders($provider) !== []) {
                continue;
            }

            /** @var array<array-key, mixed> $current */
            $current = $switches->get($key, []);

            $switches->set($key, array_merge(self::packagedConfiguration($provider, $key), $current));
        }

        return $switches;
    }

    /**
     * Tell whether the application's configuration is cached, as Laravel's
     * `mergeConfigFrom()` tells it: an application that cannot cache its
     * configuration never has.
     *
     * @param  object  $app
     * @return bool
     */
    private static function isConfigurationCached(object $app): bool
    {
        return $app instanceof CachesConfiguration && $app->configurationIsCached();
    }

    /**
     * Return the configuration a member packages under the given key, read from
     * the file its provider merges, with the environment as it stands.
     *
     * @param  class-string<\Illuminate\Support\ServiceProvider>  $provider
     * @param  string  $key
     * @return array<array-key, mixed>
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private static function packagedConfiguration(string $provider, string $key): array
    {
        $file = (new \ReflectionClass($provider))->getFileName();

        assert(is_string($file));

        $configuration = (new Filesystem)->getRequire(dirname($file, 2) . '/config/' . $key . '.php');

        assert(is_array($configuration));

        return $configuration;
    }

    /**
     * Bind the adapter over the seam with the binding's lifetime, once the seam
     * is off the container's scoped instances and, where it is still unbound,
     * once the member's listener for its being bound again is registered.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Iam\Bindings\SeamBinding  $binding
     * @return void
     */
    private function bind(Application $app, SeamBinding $binding): void
    {
        self::unscope($app, $binding->abstract);

        if ($binding->rebinding !== null && !$app->bound($binding->abstract)) {
            // @phpstan-ignore staticMethod.dynamicCall
            $app->rebinding($binding->abstract, $binding->rebinding);
        }

        match ($binding->lifetime) {
            Lifetime::TRANSIENT => $app->bind($binding->abstract, $binding->factory ?? $binding->adapter),
            Lifetime::SHARED    => $app->singleton($binding->abstract, $binding->factory ?? $binding->adapter),
            Lifetime::SCOPED    => self::bindScoped($app, $binding),
        };
    }

    /**
     * Take the seam off the container's scoped instances, where a member's
     * `scopedIf()` default puts it and where nothing else ever takes it off, so
     * neither the adapter bound over it nor a binding the application makes
     * over it later is forgotten between requests or jobs. The container lists
     * its scoped abstracts only in a protected property, the one Laravel's own
     * `forgetScopedInstances()` reads, and a container without one keeps none.
     * The list is filtered by strict comparison, never with `array_diff()`: it
     * holds the closure itself for a binding scoped by its closure's return
     * type, which `array_diff()` cannot convert to a string.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  string  $abstract
     * @return void
     */
    private static function unscope(Application $app, string $abstract): void
    {
        if (!$app instanceof IlluminateContainer) {
            return;
        }

        \Closure::bind(static function (IlluminateContainer $container) use ($abstract): void {
            $container->scopedInstances = array_filter($container->scopedInstances, static fn (mixed $scoped): bool => $scoped !== $abstract);
        }, null, IlluminateContainer::class)($app);
    }

    /**
     * Scope the adapter under this package's own key for the seam, and resolve
     * the seam through that key with a transient binding, so the seam itself
     * never joins the container's scoped instances: a binding the application
     * makes over the seam later (an instance or a singleton among them) is then
     * never forgotten between requests or jobs, while the adapter still is.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Iam\Bindings\SeamBinding  $binding
     * @return void
     */
    private static function bindScoped(Application $app, SeamBinding $binding): void
    {
        $key = self::SCOPED_PREFIX . $binding->abstract;

        $app->scoped($key, $binding->factory ?? $binding->adapter);
        $app->bind($binding->abstract, static fn (Container $container): mixed => $container->make($key));
    }
}
