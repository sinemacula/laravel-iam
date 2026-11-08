<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;

/**
 * Registers this package's checks of SSO's side with SSO's own configuration
 * checks (IAM-10.3), under the subject `iam`, through the registration point
 * SSO offers for them (`Config\ConfigurationChecks::add()`, IAM-13.12), so
 * SSO's checker is never rebound: SSO's boot check, each worker command as it
 * starts and `sso:check` run them after SSO's own.
 *
 * The registration is queued from this package's `register()` and made once
 * every provider has booted (at once when the application already has), from a
 * `booted()` callback, and again, once the application has booted, just before
 * SSO's checker is built from SSO's checks, each time it is resolved. The
 * callback is queued before SSO's own boot check whenever this package's
 * provider registers before SSO's boots; the second registration covers every
 * other order (this package's provider registered from another provider's
 * `boot()` after SSO's has booted, which queues SSO's boot check first, or
 * SSO's registered once the application has booted, after the callback found no
 * checks of SSO's to add to), so SSO's boot check, each worker command and
 * `sso:check` find it, in every provider order. It is made that late so a check
 * the application registers under `iam` itself is kept, as an application's
 * binding is (IAM-8.4), rather than refused by SSO as a second one: Laravel
 * registers the application's providers after the packages', so a registration
 * made as SSO's checks are first resolved would come before the application's
 * and make SSO refuse it. The application registers its own as SSO recommends,
 * through `callAfterResolving()` from a provider's `register()`, or from its
 * `boot()`; either lands before this, and a subject already taken is never
 * added to. SSO keeps its checks in one shared instance, so the check is added
 * once, and nothing is added while SSO's provider has not registered.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoCheckRegistration
{
    /** @var string The subject this package's checks are registered under. */
    public const string SUBJECT = 'iam';

    /** @var string The name SSO's checker's private checks are listed under among its properties. */
    private const string CHECKS = "\0" . ConfigurationChecker::class . "\0checks";

    /**
     * Register this package's checks of SSO's side with SSO's checks once the
     * application has booted, and again as SSO's checker is resolved once it
     * has.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->booted(self::addOnceBooted(...));

        /** @var \Illuminate\Foundation\Application $foundation */
        $foundation = $app;

        $app->beforeResolving(ConfigurationChecker::class, static function () use ($foundation): void {

            if (!$foundation->isBooted()) {
                return;
            }

            self::addOnceBooted($foundation);
        });
    }

    /**
     * Whether `sso:check` runs this package's check of SSO's side: SSO's
     * checker, resolved as `sso:check` resolves it, is SSO's own class and was
     * built with that check under its subject. The live checker is read, not
     * its binding or SSO's registry, so a checker the application bound itself
     * (an instance, a closure or an `extend()` building SSO's class from a list
     * of its own) is judged by the checks it holds.
     *
     * It fails closed: anything else (a check of the application's own under
     * the subject, a checker of another class, one whose checks cannot be read,
     * or one that cannot be resolved) answers `false`, so `iam:check` runs the
     * whole bridge itself (`SsoBridgeFallbackCheck`) rather than leave it
     * unrun.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return bool
     */
    public static function isInForce(Container $container): bool
    {
        try {
            $checker = $container->make(ConfigurationChecker::class);
        } catch (BindingResolutionException) {
            return false;
        }

        return (self::checksOf($checker)[self::SUBJECT] ?? null) === SsoBridgeCheck::class;
    }

    /**
     * The checks the checker resolved was built with, by subject; none where it
     * is not SSO's class (the binding is the application's to make, whatever it
     * answers with) or they cannot be read.
     *
     * SSO's checker keeps its checks to itself, with no reader, so they are
     * read from its properties as PHP lists them, private ones under their
     * mangled names, without reflection and without changing what is visible.
     *
     * @param  mixed  $checker
     * @return array<array-key, mixed>
     */
    private static function checksOf(mixed $checker): array
    {
        if (!$checker instanceof ConfigurationChecker) {
            return [];
        }

        $checks = get_mangled_object_vars($checker)[self::CHECKS] ?? [];

        return is_array($checks) ? $checks : [];
    }

    /**
     * Add the check to SSO's checks once the application has booted, unless
     * SSO's provider has not registered.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private static function addOnceBooted(Application $app): void
    {
        if (!$app->bound(ConfigurationChecks::class)) {
            return;
        }

        self::add($app->make(ConfigurationChecks::class));
    }

    /**
     * Add the check, unless something is registered under its subject.
     *
     * @param  \SineMacula\Laravel\Sso\Config\ConfigurationChecks  $checks
     * @return void
     *
     * @throws \LogicException
     */
    private static function add(ConfigurationChecks $checks): void
    {
        if (array_key_exists(self::SUBJECT, $checks->all())) {
            return;
        }

        $checks->add(self::SUBJECT, SsoBridgeCheck::class);
    }
}
