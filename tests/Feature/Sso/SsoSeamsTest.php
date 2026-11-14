<?php

declare(strict_types = 1);

namespace Tests\Feature\Sso;

use Illuminate\Config\Repository;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\External\InsufficientEvidence as InsufficientExternalEvidence;
use SineMacula\Laravel\Authentication\External\NoExternalLinks;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\ApplicationPolicyAdapter;
use SineMacula\Laravel\Iam\Sso\ExternalEvidencePolicyAdapter;
use SineMacula\Laravel\Iam\Sso\ExternalIdentityLinksAdapter;
use SineMacula\Laravel\Iam\Sso\FreshnessAdapter;
use SineMacula\Laravel\Iam\Sso\LinkConfirmationAdapter;
use SineMacula\Laravel\Iam\Sso\LinkEmailMatcherAdapter;
use SineMacula\Laravel\Iam\Sso\ReauthenticationSessionsAdapter;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Sso\Applications\ConfiguredApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy;
use SineMacula\Laravel\Sso\Evidence\InsufficientEvidence;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Linking\NoEmailMatches;
use SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;
use Tests\TestCase;

/**
 * Feature tests for the SSO seam bindings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoSeams::class)]
final class SsoSeamsTest extends TestCase
{
    /** @var array<class-string, class-string> Each seam, with the class bound over it. */
    private const array ADAPTERS = [
        ReauthenticationSessions::class => ReauthenticationSessionsAdapter::class,
        SessionRevocation::class        => SessionRevocationAdapter::class,
        ExternalIdentityLinks::class    => ExternalIdentityLinksAdapter::class,
        Linker::class                   => LinkStore::class,
        ExternalEvidencePolicy::class   => ExternalEvidencePolicyAdapter::class,
        Freshness::class                => FreshnessAdapter::class,
        ApplicationPolicy::class        => ApplicationPolicyAdapter::class,
        LinkEmailMatcher::class         => LinkEmailMatcherAdapter::class,
        LinkConfirmation::class         => LinkConfirmationAdapter::class,
    ];

    /** @var array<class-string, class-string> Each seam SSO or `laravel-authentication` binds a default for, with that default. */
    private const array MEMBER_DEFAULTS = [
        ReauthenticationSessions::class => NoReauthenticationSessions::class,
        SessionRevocation::class        => NoSessionRevocation::class,
        ExternalIdentityLinks::class    => NoExternalLinks::class,
        Linker::class                   => NoLinks::class,
        ExternalEvidencePolicy::class   => InsufficientExternalEvidence::class,
        Freshness::class                => RefusingFreshness::class,
        ApplicationPolicy::class        => ConfiguredApplicationPolicy::class,
        LinkEmailMatcher::class         => NoEmailMatches::class,
        LinkConfirmation::class         => RefusingLinkConfirmation::class,
        EvidencePolicy::class           => InsufficientEvidence::class,
    ];

    /** @var list<class-string> The members' own classes bound scoped over a seam. */
    private const array SCOPED = [LinkStore::class, ConnectionEvidencePolicy::class];

    /**
     * Every adapter and SSO's link store is bound over its member's default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEveryAdapterIsBoundOverItsMembersDefault(): void
    {
        $this->assertResolvesTo([
            ...self::ADAPTERS,
            EvidencePolicy::class => InsufficientEvidence::class,
        ]);
    }

    /**
     * With the switch off every member keeps its own default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testTheSwitchOffBindsNothing(): void
    {
        $this->assertResolvesTo(self::MEMBER_DEFAULTS);
    }

    /**
     * The evidence switch binds SSO's per-connection evidence policy, scoped.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(SsoSeams::EVIDENCE_SWITCH, true, defer: false)]
    public function testTheEvidenceSwitchBindsAScopedConnectionEvidencePolicy(): void
    {
        $this->assertScopedAndForgotten(EvidencePolicy::class, ConnectionEvidencePolicy::class);
    }

    /**
     * With the capability off the evidence switch binds nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    #[WithConfig(SsoSeams::EVIDENCE_SWITCH, true, defer: false)]
    public function testTheEvidenceSwitchBindsNothingWithTheCapabilityOff(): void
    {
        $this->assertResolvesTo([EvidencePolicy::class => InsufficientEvidence::class]);
    }

    /**
     * The link store is scoped and forgotten when the worker resets.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheLinkStoreIsScopedAndForgottenWhenTheWorkerResets(): void
    {
        $this->assertScopedAndForgotten(Linker::class, LinkStore::class);
    }

    /**
     * Evidence switch values, and whether each binds the evidence policy.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideEvidenceSwitchValues(): iterable
    {
        yield 'true' => [true, true];

        yield 'true as text' => ['true', true];

        yield 'one' => ['1', true];

        yield 'on' => ['on', true];

        yield 'yes' => ['yes', true];

        yield 'missing' => [null, false];

        yield 'empty' => ['', false];

        yield 'unrecognised' => ['sometimes', false];

        yield 'a list' => [[true], false];

        yield 'false' => [false, false];

        yield 'off' => ['off', false];
    }

    /**
     * The evidence switch is read strictly, and binds only with the capability
     * on.
     *
     * @param  mixed  $value
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideEvidenceSwitchValues')]
    public function testTheEvidenceSwitchIsReadStrictly(mixed $value, bool $on): void
    {
        $config = new Repository(['iam' => ['sso' => ['evidence' => $value]]]);
        $off    = new Repository(['iam' => ['adapters' => ['sso' => false], 'sso' => ['evidence' => $value]]]);

        self::assertSame($on, SsoSeams::isEvidenceOn($config));
        self::assertSame($on, self::bindingOf(EvidencePolicy::class, $config)->on);
        self::assertFalse(self::bindingOf(EvidencePolicy::class, $off)->on);
    }

    /**
     * Switch values, and whether each leaves the bindings on.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideSwitchValues(): iterable
    {
        yield 'true' => [true, true];

        yield 'missing' => [null, true];

        yield 'empty' => ['', true];

        yield 'on' => ['on', true];

        yield 'one' => ['1', true];

        yield 'unrecognised' => ['sometimes', true];

        yield 'false' => [false, false];

        yield 'false as text' => ['false', false];

        yield 'zero' => ['0', false];

        yield 'off' => ['off', false];

        yield 'no' => ['no', false];
    }

    /**
     * The switch is read leniently.
     *
     * @param  mixed  $value
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideSwitchValues')]
    public function testTheSwitchIsReadLeniently(mixed $value, bool $on): void
    {
        $config = new Repository(['iam' => ['adapters' => ['sso' => $value]]]);

        self::assertSame($on, SsoSeams::isOn($config));

        foreach ((new SsoSeams)->seams($config) as $binding) {
            self::assertSame($on && $binding->abstract !== EvidencePolicy::class, $binding->on, $binding->abstract);
        }
    }

    /**
     * MFA's switch off leaves SSO's bindings on.
     *
     * @return void
     */
    public function testOnlySsosSwitchIsRead(): void
    {
        self::assertTrue(SsoSeams::isOn(new Repository(['iam' => ['adapters' => ['mfa' => false]]])));
    }

    /**
     * Each binding's lifetime and mandate while SSO is out of use.
     *
     * @return void
     */
    public function testEachBindingsLifetimeAndMandate(): void
    {
        $bindings = (new SsoSeams)->seams(new Repository);

        self::assertSame([...self::ADAPTERS, EvidencePolicy::class => ConnectionEvidencePolicy::class], array_combine(
            array_map(static fn (SeamBinding $binding): string => $binding->abstract, $bindings),
            array_map(static fn (SeamBinding $binding): string => $binding->adapter, $bindings),
        ));

        foreach ($bindings as $binding) {
            self::assertSame(in_array($binding->adapter, self::SCOPED, true) ? Lifetime::SCOPED : Lifetime::TRANSIENT, $binding->lifetime, $binding->abstract);
            self::assertSame($binding->abstract === SessionRevocation::class, $binding->isMandatory(), $binding->abstract);
        }
    }

    /**
     * Configurations, and the seams each makes mandatory.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<class-string>}>
     */
    public static function provideMandates(): iterable
    {
        yield 'sso in use' => [['sso' => ['features' => ['oidc' => true]]], [SessionRevocation::class, ExternalIdentityLinks::class, Linker::class]];

        yield 'enforcement on' => [[TenancySeams::ENFORCEMENT => true], [ReauthenticationSessions::class, SessionRevocation::class]];
    }

    /**
     * The links are mandatory while SSO is in use, and the re-authentication
     * sessions while it enforces.
     *
     * @param  array<string, mixed>  $configuration
     * @param  list<class-string>  $mandatory
     * @return void
     */
    #[DataProvider('provideMandates')]
    public function testTheMandatesFollowTheConfiguration(array $configuration, array $mandatory): void
    {
        $config = new Repository;

        foreach ($configuration as $key => $value) {
            $config->set($key, $value);
        }

        $bindings = array_filter((new SsoSeams)->seams($config), static fn (SeamBinding $binding): bool => $binding->isMandatory());

        self::assertSame($mandatory, array_values(array_map(static fn (SeamBinding $binding): string => $binding->abstract, $bindings)));
    }

    /**
     * The table's binding of the seam under the configuration.
     *
     * @param  class-string  $abstract
     * @param  \Illuminate\Config\Repository  $config
     * @return \SineMacula\Laravel\Iam\Bindings\SeamBinding
     */
    private static function bindingOf(string $abstract, Repository $config): SeamBinding
    {
        foreach ((new SsoSeams)->seams($config) as $binding) {
            if ($binding->abstract === $abstract) {
                return $binding;
            }
        }

        return self::fail(sprintf('The table declares no binding of [%s].', $abstract));
    }

    /**
     * Assert the seam resolves to one scoped instance until the worker resets.
     *
     * @param  class-string  $abstract
     * @param  class-string  $class
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertScopedAndForgotten(string $abstract, string $class): void
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        $first = $app->make($abstract);

        self::assertInstanceOf($class, $first);
        self::assertSame($first, $app->make($abstract));
        self::assertTrue($app->isShared(SeamBinding::SCOPED_PREFIX . $abstract));
        self::assertFalse($app->isShared($abstract));

        Iam::resetWorkerState();

        self::assertNotSame($first, $app->make($abstract));
    }

    /**
     * Assert each seam resolves to an instance of the given class.
     *
     * @param  array<class-string, class-string>  $expected
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertResolvesTo(array $expected): void
    {
        foreach ($expected as $abstract => $concrete) {
            self::assertInstanceOf($concrete, $this->app?->make($abstract), $abstract);
        }
    }
}
