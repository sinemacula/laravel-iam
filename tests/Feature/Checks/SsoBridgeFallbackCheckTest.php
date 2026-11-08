<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Iam\Checks\SsoBridgeFallbackCheck;
use SineMacula\Laravel\Iam\Checks\SsoCheckRegistration;
use SineMacula\Laravel\Sso\Config\Checks\FeaturesCheck;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Concerns\RunsChecks;
use Tests\TestCase;

/**
 * Feature tests for `iam:check` running this package's check of SSO's side
 * itself while SSO is in use and `sso:check` does not run it (IAM-2.5,
 * IAM-10.2): every SSO application's `external_provider` sign-in method, every
 * application's `unlinked_handoffs` and the mandatory seams of SSO's flows,
 * reported once, whichever runs them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoBridgeFallbackCheck::class)]
#[CoversClass(SsoCheckRegistration::class)]
final class SsoBridgeFallbackCheckTest extends TestCase
{
    use RunsChecks;

    /** @var string Why an application handing off unlinked results is refused. */
    private const string UNLINKED = '`sso.applications.api.unlinked_handoffs` must stay off under laravel-iam: an unlinked result is provisioned or refused, never handed off.';

    /** @var string Why an application whose guard does not allow an external sign-in is refused. */
    private const string NO_EXTERNAL_SIGN_IN = '`sso.applications.api` is served by SSO, '
        . 'but its guard does not list `external_provider` among laravel-authentication\'s sign-in methods.';

    /**
     * Rows of how `sso:check` comes not to run this package's check of SSO's
     * side: the application registered a check of its own under its subject,
     * which the registration keeps, bound a checker of its own (SSO's own class
     * built from a list without the bridge, as an instance or through
     * `extend()`, included), or SSO's checks are not bound at all.
     *
     * @return iterable<string, array{\Closure(\Illuminate\Contracts\Foundation\Application): void}>
     */
    public static function bridgeNotInForce(): iterable
    {
        yield 'the application\'s own check under the subject' => [static function (Application $app): void {
            $checks = [...SsoServiceProvider::CONFIGURATION_CHECKS, SsoCheckRegistration::SUBJECT => FeaturesCheck::class];

            $app->instance(ConfigurationChecks::class, new ConfigurationChecks($checks));
        }];
        yield 'a checker of the application\'s' => [static function (Application $app): void {
            $app->bind(ConfigurationChecker::class, static fn (): ?object => null);
        }];
        yield 'SSO\'s class built without the bridge' => [static function (Application $app): void {
            $app->instance(ConfigurationChecker::class, new ConfigurationChecker($app, SsoServiceProvider::CONFIGURATION_CHECKS));
        }];
        yield 'SSO\'s class extended without the bridge' => [static function (Application $app): void {
            $app->extend(
                ConfigurationChecker::class,
                static fn (ConfigurationChecker $checker, Application $app): ConfigurationChecker => new ConfigurationChecker($app, SsoServiceProvider::CONFIGURATION_CHECKS),
            );
        }];
        yield 'SSO\'s checks unbound' => [static function (Application $app): void {
            assert($app instanceof \ArrayAccess);

            unset($app[ConfigurationChecks::class]);
        }];
    }

    /**
     * When `sso:check` does not run this package's check of SSO's side,
     * `iam:check` runs every one of its checks: an application handing off
     * unlinked results, one whose guard does not allow an external sign-in, and
     * a mandatory seam of SSO's flows on a member's class are each refused
     * here, and the seam is not refused a second time by the mandatory seams'
     * check.
     *
     * @param  \Closure(\Illuminate\Contracts\Foundation\Application): void  $takeOut
     * @return void
     */
    #[DataProvider('bridgeNotInForce')]
    public function testTheWholeBridgeRunsHereWhenSsosCheckDoesNotRunIt(\Closure $takeOut): void
    {
        $this->useSso();

        $this->app?->bind(LinkStorage::class, NoLinks::class);

        $takeOut($this->app);

        $problems = self::problems($this->check()->checks());

        self::assertFalse(SsoCheckRegistration::isInForce($this->application()));
        self::assertTrue($this->check()->applies());
        self::assertSame([self::NO_EXTERNAL_SIGN_IN, self::UNLINKED], array_slice($problems, 0, 2));
        self::assertCount(1, array_filter($problems, static fn (string $problem): bool => str_starts_with($problem, LinkStorage::class . ' is still bound to ' . NoLinks::class)));
        self::assertSame([], self::problems($this->seams()->checks()));
    }

    /**
     * While `sso:check` runs this package's check of SSO's side, `iam:check`
     * leaves it to SSO's check, so nothing is reported twice.
     *
     * @return void
     */
    public function testItDoesNotApplyWhileSsosCheckRunsTheBridge(): void
    {
        $this->useSso();

        self::assertTrue(SsoCheckRegistration::isInForce($this->application()));
        self::assertFalse($this->check()->applies());
    }

    /**
     * A checker of SSO's own class the application bound itself, built with
     * this package's check of SSO's side under its subject, runs the bridge in
     * `sso:check`, so `iam:check` leaves it to SSO's check.
     *
     * @return void
     */
    public function testACheckerOfSsosClassHoldingTheBridgeRunsIt(): void
    {
        $this->useSso();

        $app    = $this->application();
        $checks = [...SsoServiceProvider::CONFIGURATION_CHECKS, SsoCheckRegistration::SUBJECT => SsoBridgeCheck::class];

        $app->instance(ConfigurationChecks::class, new ConfigurationChecks([]));
        $app->instance(ConfigurationChecker::class, new ConfigurationChecker($app, $checks));

        self::assertTrue(SsoCheckRegistration::isInForce($app));
        self::assertFalse($this->check()->applies());
    }

    /**
     * While SSO is not in use, the bridge does not apply, wherever it would
     * run.
     *
     * @return void
     */
    public function testItDoesNotApplyWhileSsoIsNotInUse(): void
    {
        $this->application()->instance(ConfigurationChecks::class, new ConfigurationChecks([SsoCheckRegistration::SUBJECT => FeaturesCheck::class]));

        self::assertFalse($this->check()->applies());
    }

    /**
     * Where whether `sso:check` runs the bridge cannot be read, the check
     * applies, so the bridge runs rather than go unrun.
     *
     * @return void
     */
    public function testItAppliesWhereSsosCheckCannotBeRead(): void
    {
        $this->useSso();

        $this->application()->bind(ConfigurationChecks::class, static function (): never {
            throw new BindingResolutionException('SSO\'s checks cannot be built.');
        });

        self::assertTrue($this->check()->applies());
    }

    /**
     * Its findings are reported under the subject `sso`, and they are the
     * bridge's own.
     *
     * @return void
     */
    public function testItReportsTheBridgesChecksUnderItsSubject(): void
    {
        $this->useSso();

        $bridge = $this->application()->make(SsoBridgeCheck::class);

        self::assertSame('sso', $this->check()->subject());
        self::assertCount(count($bridge->checks()), $this->check()->checks());
    }

    /**
     * Put SSO in use, with an application served whose guard does not allow an
     * external sign-in and whose unlinked handoffs are on.
     *
     * @return void
     */
    private function useSso(): void
    {
        $config = $this->application()->make('config');

        $config->set('sso.features.saml2', true);
        $config->set('sso.applications.api.unlinked_handoffs', true);
    }

    /**
     * The application the test booted.
     *
     * @return \Illuminate\Contracts\Foundation\Application
     */
    private function application(): Application
    {
        $app = $this->app;

        assert($app instanceof Application);

        return $app;
    }

    /**
     * The check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\SsoBridgeFallbackCheck
     */
    private function check(): SsoBridgeFallbackCheck
    {
        return $this->application()->make(SsoBridgeFallbackCheck::class);
    }

    /**
     * The mandatory seams' check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck
     */
    private function seams(): MandatorySeamsCheck
    {
        return $this->application()->make(MandatorySeamsCheck::class);
    }
}
