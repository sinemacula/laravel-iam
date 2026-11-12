<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Iam\Authorization\AccessMandates;
use SineMacula\Laravel\Iam\Authorization\ApplicationAccessAdapter;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\ScopeRegistryAdapter;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Facades\Iam;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Authorization\CredentialScopes;
use Tests\TestCase;

/**
 * Feature tests for the machine scope cap and application access seams.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AccessMandates::class)]
#[CoversClass(MandatorySeamsCheck::class)]
final class AccessSeamsTest extends TestCase
{
    use RunsChecks;

    /** @var ?class-string The session policy source the application names in `laravel-authorization`'s configuration. */
    private ?string $namedSource = null;

    /** @var bool Whether the capability's switch is on. */
    private bool $switchOn = true;

    /**
     * A source named in `laravel-authorization`'s configuration is kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testASourceNamedInAuthorizationsConfigurationIsKept(): void
    {
        $this->namedSource = CredentialScopes::class;

        $this->refreshApplication();

        self::assertInstanceOf(CredentialScopes::class, $this->resolve(SessionPolicySource::class));
    }

    /**
     * Application access is forgotten by the worker reset.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testApplicationAccessIsForgottenBetweenUnitsOfWork(): void
    {
        $app   = $this->app ?? self::fail('The application has not booted.');
        $first = $this->resolve(ApplicationAccess::class);

        self::assertInstanceOf(ApplicationAccessAdapter::class, $first);
        self::assertSame($first, $this->resolve(ApplicationAccess::class));
        self::assertTrue($app->bound(SeamBinding::SCOPED_PREFIX . ApplicationAccess::class));
        self::assertFalse($app->isShared(ApplicationAccess::class));

        Iam::resetWorkerState();

        self::assertNotSame($first, $this->resolve(ApplicationAccess::class));
    }

    /**
     * While mandatory, `iam:check` passes the adapters.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIamCheckPassesTheAdaptersWhileMandatory(): void
    {
        $this->acceptApiKeys();
        $this->app?->make('config')->set(AccessMandates::APPLICATION_ACCESS, ['api' => 'api:use']);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * With the switch off, `iam:check` refuses mandatory member defaults.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
    public function testIamCheckRefusesTheDefaultsWhileMandatory(): void
    {
        $this->acceptApiKeys();
        $this->app?->make('config')->set(AccessMandates::APPLICATION_ACCESS, ['api' => 'api:use']);

        self::assertInstanceOf(NoSessionPolicy::class, $this->resolve(SessionPolicySource::class));

        $problems = self::problems($this->check()->checks());

        self::assertCount(3, $problems);
        self::assertStringStartsWith(SessionPolicySource::class . ' is still bound to its member\'s', $problems[0]);
        self::assertStringStartsWith(ScopeRegistry::class . ' is still bound to its member\'s', $problems[1]);
        self::assertStringStartsWith(ApplicationAccess::class . ' is still bound to its member\'s', $problems[2]);
    }

    /**
     * Rows of `[whether the capability's switch is on]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideSwitchStates(): iterable
    {
        yield 'on' => [true];

        yield 'off' => [false];
    }

    /**
     * A source named in authorization's config passes `iam:check`.
     *
     * @param  bool  $on
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideSwitchStates')]
    public function testIamCheckPassesASourceNamedInAuthorizationsConfiguration(bool $on): void
    {
        $this->namedSource = CredentialScopes::class;
        $this->switchOn    = $on;

        $this->refreshApplication();
        $this->acceptApiKeys();

        $this->app?->singleton(ScopeRegistry::class, ScopeRegistryAdapter::class);

        self::assertInstanceOf(CredentialScopes::class, $this->resolve(SessionPolicySource::class));
        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * The bound application policy says which credentials a guard accepts.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
    public function testIamCheckAsksTheBoundApplicationPolicy(): void
    {
        $accepting = self::createStub(ApplicationPolicy::class);
        $refusing  = self::createStub(ApplicationPolicy::class);

        $accepting->method('allowsMethod')->willReturnCallback(static fn (string $guard, string $method): bool => $guard === self::GUARD && $method === 'client_credentials');
        $refusing->method('allowsMethod')->willThrowException(new \InvalidArgumentException('The guard\'s settings are not set.'));

        $app = $this->app ?? self::fail('The application has not booted.');

        $app->instance(ApplicationPolicy::class, $accepting);

        self::assertFalse(AccessMandates::acceptsMachineCredentials($app->make('config')));

        $problems = self::problems($this->check()->checks());

        self::assertCount(2, $problems);
        self::assertStringStartsWith(SessionPolicySource::class, $problems[0]);
        self::assertStringStartsWith(ScopeRegistry::class, $problems[1]);

        $app->instance(ApplicationPolicy::class, $refusing);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * Load the configuration with the test's switch and source applied.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        if (!$this->switchOn) {
            $app->make('config')->set(AuthorizationSeams::SWITCH, false);
        }

        if ($this->namedSource === null) {
            return;
        }

        $app->make('config')->set('authorization.session', ['source' => $this->namedSource, 'scopes' => []]);
    }

    /**
     * Have a guard accept API keys.
     *
     * @return void
     */
    private function acceptApiKeys(): void
    {
        $this->app?->make('config')->set('auth.guards.keys', ['driver' => 'api_key', 'provider' => 'people', 'application' => ['methods' => ['api_key']]]);
    }

    /**
     * Resolve the seam given.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolve(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }

    /**
     * The check of the mandatory seams.
     *
     * @return \SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function check(): MandatorySeamsCheck
    {
        $check = $this->app?->make(MandatorySeamsCheck::class);

        self::assertInstanceOf(MandatorySeamsCheck::class, $check);

        return $check;
    }
}
