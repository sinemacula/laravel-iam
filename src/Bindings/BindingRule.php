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
        $switches = self::switches($app);
        $bindings = array_merge(...array_map(static fn (ProvidesSeams $capability): array => $capability->seams($switches), $capabilities));
        $bound    = [];
        $kept     = [];

        foreach ($bindings as $binding) {

            if ($binding->appliesWhen !== null && !($binding->appliesWhen)($switches)) {
                continue;
            }

            if (!$this->defaults->isReplaceable($app, $binding->abstract, $binding->memberDefaults)) {
                $kept[] = $binding->abstract;

                continue;
            }

            $this->bind($app, $binding);

            $bound[] = $binding->abstract;
        }

        return new BindingOutcome($bound, $kept);
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
     * is off the container's scoped instances.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Iam\Bindings\SeamBinding  $binding
     * @return void
     */
    private function bind(Application $app, SeamBinding $binding): void
    {
        self::unscope($app, $binding->abstract);

        match ($binding->lifetime) {
            Lifetime::TRANSIENT => $app->bind($binding->abstract, $binding->adapter),
            Lifetime::SHARED    => $app->singleton($binding->abstract, $binding->adapter),
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

        $app->scoped($key, $binding->adapter);
        $app->bind($binding->abstract, static fn (Container $container): mixed => $container->make($key));
    }
}
