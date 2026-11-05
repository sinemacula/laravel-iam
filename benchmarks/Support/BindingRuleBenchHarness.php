<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Binding rule benchmark fixtures: applications with every member's provider
 * registered, not booted, so the rule reads the binding table the members
 * really leave when this package registers after them, and the seam table of
 * `BenchSeamTable` to apply over it.
 *
 * Three paths are timed: every seam still unbound or bound to its member's
 * default, so every adapter is bound; every seam bound by the application, so
 * every binding is kept; and every switch off, so nothing is read. Binding over
 * a default changes the table, so that path takes a fresh copy of the
 * application from a pool made in advance, keeping the copy out of the time.
 * The applications' configuration is not cached, so every path includes reading
 * each member's packaged configuration beneath the application's for the
 * switches, as the rule does whenever the configuration is not cached.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BindingRuleBenchHarness
{
    /** @var list<class-string<\Illuminate\Support\ServiceProvider>> The members' providers, in the order Composer discovers them. */
    private const array MEMBER_PROVIDERS = [
        AuditLogServiceProvider::class,
        AuthenticationServiceProvider::class,
        AuthorizationServiceProvider::class,
        MfaServiceProvider::class,
        SsoServiceProvider::class,
    ];

    /** @var int Number of fresh applications for the path that binds over the defaults. */
    private const int POOL_SIZE = 160;

    /** @var \SineMacula\Laravel\Iam\Bindings\BindingRule */
    private readonly BindingRule $rule;

    /** @var \Benchmarks\Support\BenchSeamTable The capability whose seam table is applied. */
    private readonly BenchSeamTable $table;

    /** @var \Illuminate\Foundation\Application Every seam bound by the application in a `register()`. */
    private readonly Application $applicationBound;

    /** @var \Illuminate\Foundation\Application Every switch the table reads turned off. */
    private readonly Application $switchedOff;

    /** @var list<\Illuminate\Foundation\Application> Copies of an application holding only the members' defaults. */
    private array $memberDefaults = [];

    /** @var int Current index into the pool of member default applications. */
    private int $memberDefaultsIndex = 0;

    /**
     * Build the applications and the seam table, and check that each path
     * reaches the outcome it measures.
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function __construct()
    {
        $memberDefaults   = self::application([]);
        $applicationBound = self::application([]);
        $switchedOff      = self::application(['iam' => ['adapters' => array_fill_keys(BenchSeamTable::switches(), false)]]);

        foreach (BenchSeamTable::abstracts() as $seam) {
            $applicationBound->bind($seam, \stdClass::class);
        }

        $this->rule             = $memberDefaults->make(BindingRule::class);
        $this->table            = new BenchSeamTable;
        $this->applicationBound = $applicationBound;
        $this->switchedOff      = $switchedOff;

        for ($index = 0; $index < self::POOL_SIZE; $index++) {
            $this->memberDefaults[] = clone $memberDefaults;
        }

        $this->assertEachPathReachesItsOutcome(clone $memberDefaults);
    }

    /**
     * Benchmark binding every adapter over the members' defaults.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function runOverMemberDefaults(): void
    {
        $this->rule->apply($this->nextMemberDefaults(), $this->table);
    }

    /**
     * Benchmark keeping every binding the application made.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function runOverApplicationBindings(): void
    {
        $this->rule->apply($this->applicationBound, $this->table);
    }

    /**
     * Benchmark a table whose every switch is off.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function runSwitchedOff(): void
    {
        $this->rule->apply($this->switchedOff, $this->table);
    }

    /**
     * Run each benchmarked path once and throw unless it reaches the outcome
     * its name describes: over the members' defaults every seam is bound, over
     * the application's bindings every seam is kept, and with every switch off
     * no seam is either. The defaults path runs on a copy of its own, so the
     * pool is untouched.
     *
     * @param  \Illuminate\Foundation\Application  $memberDefaults
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function assertEachPathReachesItsOutcome(Application $memberDefaults): void
    {
        $seams = BenchSeamTable::abstracts();

        self::assertOutcome('member defaults', $this->rule->apply($memberDefaults, $this->table), $seams, []);
        self::assertOutcome('application bindings', $this->rule->apply($this->applicationBound, $this->table), [], $seams);
        self::assertOutcome('switched off', $this->rule->apply($this->switchedOff, $this->table), [], []);
    }

    /**
     * Throw unless the path bound and kept exactly the seams given.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\Iam\Bindings\BindingOutcome  $outcome
     * @param  list<class-string>  $bound
     * @param  list<class-string>  $kept
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertOutcome(string $path, BindingOutcome $outcome, array $bound, array $kept): void
    {
        if ($outcome->bound !== $bound || $outcome->kept !== $kept) {
            throw new \LogicException(sprintf('The %s benchmark does not reach the outcome it measures; fix its fixtures before timing it.', $path));
        }
    }

    /**
     * Take the next unused application from the member defaults pool, throwing
     * once the pool is used up, so a run with more revolutions than the pool
     * holds fails instead of timing the rule keeping its own adapters.
     *
     * @return \Illuminate\Foundation\Application
     *
     * @throws \LogicException
     */
    private function nextMemberDefaults(): Application
    {
        if (!array_key_exists($this->memberDefaultsIndex, $this->memberDefaults)) {
            throw new \LogicException(sprintf('The member defaults benchmark has used up its %d applications; give it a larger pool or fewer revolutions.', self::POOL_SIZE));
        }

        return $this->memberDefaults[$this->memberDefaultsIndex++];
    }

    /**
     * Build an application over the configuration given, with every member's
     * provider registered and none booted, as the binding rule finds it when
     * this package registers after them.
     *
     * @param  array<string, mixed>  $config
     * @return \Illuminate\Foundation\Application
     */
    private static function application(array $config): Application
    {
        $app = new Application(dirname(__DIR__, 2));

        $app->instance('config', new ConfigRepository($config));
        $app->instance('events', new Dispatcher($app));

        Container::setInstance($app);

        foreach (self::MEMBER_PROVIDERS as $provider) {
            $app->register($provider);
        }

        return $app;
    }
}
