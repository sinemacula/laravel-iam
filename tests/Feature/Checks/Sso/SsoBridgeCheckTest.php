<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks\Sso;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use Tests\Concerns\RunsChecks;
use Tests\TestCase;

/**
 * Feature tests for the SSO bridge check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoBridgeCheck::class)]
#[CoversClass(SsoSeams::class)]
#[CoversClass(MandatorySeamsCheck::class)]
#[CoversClass(TenancySeams::class)]
final class SsoBridgeCheckTest extends TestCase
{
    use RunsChecks;

    /** @var \Illuminate\Container\Container The application's container, the policy and the seams bound in it. */
    private Container $container;

    /** @var \Illuminate\Config\Repository The configuration the checks read. */
    private Repository $config;

    /**
     * Configure SSO and bind every mandatory seam as this package needs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = $this->app ?? self::fail('The application has not booted.');
        $this->config    = new Repository([
            'database' => ['default' => 'main'],
            'iam'      => ['storage' => ['connection' => null]],
            'sso'      => [
                'features'     => ['saml2' => true],
                'applications' => ['api' => ['unlinked_handoffs' => false], 'admin' => []],
                'endpoints'    => ['base_url' => 'https://sso.test'],
                'storage'      => ['connection' => 'main'],
            ],
        ]);

        $policy = \Mockery::mock(ApplicationPolicy::class);
        $policy->shouldReceive('allowsMethod')->andReturnUsing(static fn (string $guard): bool => in_array($guard, ['api', 'admin'], true));

        $this->container->instance(ApplicationPolicy::class, $policy);

        foreach ([SessionRevocation::class, ExternalIdentityLinks::class, Linker::class] as $seam) {
            $this->container->instance($seam, \Mockery::mock($seam));
        }
    }

    /**
     * Rows of `[features, in use]`, as SSO's `Features::isInUse()` reads them.
     *
     * @return iterable<string, array{array<string, mixed>, bool}>
     */
    public static function provideFeatures(): iterable
    {
        yield 'nothing on' => [[], false];
        yield 'both off' => [['saml2' => false, 'oidc' => 'false'], false];
        yield 'off as digits' => [['saml2' => 0, 'oidc' => '0'], false];
        yield 'SAML on' => [['saml2' => true], true];
        yield 'OIDC on as text' => [['oidc' => 'true'], true];
        yield 'a malformed switch' => [['saml2' => 'off'], true];
        yield 'a null switch' => [['oidc' => null], true];
    }

    /**
     * The checks apply only while SSO is in use.
     *
     * @param  array<string, mixed>  $features
     * @param  bool  $inUse
     * @return void
     */
    #[DataProvider('provideFeatures')]
    public function testItAppliesOnlyWhileSsoIsInUse(array $features, bool $inUse): void
    {
        $this->config->set('sso.features', $features);

        self::assertSame($inUse, $this->check()->applies());
        self::assertSame('sso', $this->check()->subject());
        self::assertSame($inUse, SsoSeams::isInUse($this->config));
    }

    /**
     * SSO configured as this package needs passes.
     *
     * @return void
     */
    public function testAConfigurationThatHoldsPasses(): void
    {
        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * Each application's sign-in method and handoffs are checked.
     *
     * @return void
     */
    public function testEachApplicationIsChecked(): void
    {
        $this->config->set('sso.applications', ['portal' => ['unlinked_handoffs' => 'true'], 'admin' => ['unlinked_handoffs' => '0']]);

        self::assertSame([
            '`sso.applications.portal` is served by SSO, but its guard does not list `external_provider` among laravel-authentication\'s sign-in methods.',
            '`sso.applications.portal.unlinked_handoffs` must stay off under laravel-iam: an unlinked result is provisioned or refused, never handed off.',
        ], self::problems($this->check()->checks()));

        $this->config->set('sso.applications', [['unlinked_handoffs' => true]]);

        self::assertSame([
            '`sso.applications.0` is served by SSO, but its guard does not list `external_provider` among laravel-authentication\'s sign-in methods.',
            '`sso.applications.0.unlinked_handoffs` must stay off under laravel-iam: an unlinked result is provisioned or refused, never handed off.',
        ], self::problems($this->check()->checks()));

        $this->config->set('sso.applications', 'not a map');

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * The base URL and storage connection are left to their own checks.
     *
     * @return void
     */
    public function testTheBaseUrlAndTheStorageConnectionAreLeftToTheirOwners(): void
    {
        $this->config->set('sso.endpoints.base_url', ' ');
        $this->config->set('iam.storage.connection', 'shared');
        $this->config->set('sso.storage.connection', 'elsewhere');

        self::assertSame([], self::problems($this->check()->checks()));
        self::assertSame([SsoSeams::class, TenancySeams::class], SsoBridgeCheck::CAPABILITIES);
    }

    /**
     * Each unbound mandatory seam of SSO's flows is refused.
     *
     * @return void
     */
    public function testTheMandatorySeamsAreChecked(): void
    {
        $this->container->offsetUnset(SessionRevocation::class);
        $this->container->offsetUnset(Linker::class);

        $problems = self::problems($this->check()->checks());

        self::assertCount(2, $problems);
        self::assertStringStartsWith(SessionRevocation::class . ' is unbound', $problems[0]);
        self::assertStringStartsWith(Linker::class . ' is unbound', $problems[1]);
    }

    /**
     * Without a container, a tenant rule is read from configuration alone.
     *
     * @return void
     */
    public function testATenantsRuleIsReadFromTheConfigurationAloneWithoutAContainer(): void
    {
        self::assertFalse(TenancySeams::isEnforcedOrRequired($this->config, null));

        $this->config->set(TenancySeams::ENFORCEMENT, true);

        self::assertTrue(TenancySeams::isEnforcedOrRequired($this->config, null));
    }

    /**
     * The check, built as `iam:check` builds it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck
     */
    private function check(): SsoBridgeCheck
    {
        $seams = new MandatorySeamsCheck($this->container, $this->config);

        return new SsoBridgeCheck($this->container, $this->config, $seams);
    }
}
