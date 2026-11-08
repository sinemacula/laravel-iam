<?php

declare(strict_types = 1);

namespace Tests\Unit\Checks\Sso;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Iam\Bindings\MemberDefaults;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Checks\SeamHolders;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use Tests\Concerns\RunsChecks;

/**
 * Unit tests for this package's checks of SSO's side (IAM-10.3, IAM-2.5): they
 * apply only while SSO is in use, so they fail SSO's boot only then (decision
 * Q12), and check each application's sign-in method and unlinked handoffs and
 * the mandatory seams of SSO's flows, leaving the base URL to SSO's own check
 * and the storage connection to the storage alignment.
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

    /** @var \Illuminate\Container\Container The container the policy and the seams are bound in. */
    private Container $container;

    /** @var \Illuminate\Config\Repository The configuration the checks read. */
    private Repository $config;

    /**
     * Start every test with a container holding a policy that allows
     * `external_provider` for the `api` guard alone, every mandatory seam bound
     * to an implementation of the application's, and SSO configured as this
     * package needs it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
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

        $this->container->instance(ContainerContract::class, $this->container);
        $this->container->instance(ApplicationPolicy::class, $policy);

        foreach ([SessionRevocation::class, ExternalIdentityLinks::class, Linker::class, LinkStorage::class] as $seam) {
            $this->container->instance($seam, \Mockery::mock($seam));
        }
    }

    /**
     * Close Mockery's expectations.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * Rows of `[features, in use]`: SSO is in use while a protocol is on, or
     * its switch is malformed, as SSO's own `Features::isInUse()` reads it.
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
        self::assertSame($inUse, SsoSeams::isInUse($this->config));
    }

    /**
     * SSO configured as this package needs it, every mandatory seam bound to
     * the application's own, passes.
     *
     * @return void
     */
    public function testAConfigurationThatHoldsPasses(): void
    {
        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * An application whose guard does not allow `external_provider`, or one
     * handing off unlinked results, is refused, one listed rather than named
     * included.
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
     * The base URL and the storage connection are not this check's: SSO's own
     * `EndpointsCheck` refuses a base URL unset, and the storage alignment a
     * storage connection elsewhere, at boot and in `iam:check`, so each is
     * reported once.
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
     * The mandatory seams of SSO's flows are checked: each one unbound is
     * refused.
     *
     * @return void
     */
    public function testTheMandatorySeamsAreChecked(): void
    {
        $this->container->offsetUnset(SessionRevocation::class);
        $this->container->offsetUnset(LinkStorage::class);

        $problems = self::problems($this->check()->checks());

        self::assertCount(2, $problems);
        self::assertStringStartsWith(SessionRevocation::class . ' is unbound', $problems[0]);
        self::assertStringStartsWith(LinkStorage::class . ' is unbound', $problems[1]);
    }

    /**
     * With no container to read, a tenant's rule is on only by the
     * configuration: SSO's enforcement, or a requirement named.
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
     * The check, built as SSO's checker builds it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck
     */
    private function check(): SsoBridgeCheck
    {
        $seams = new MandatorySeamsCheck($this->container, $this->config, new SeamHolders(new MemberDefaults));

        return new SsoBridgeCheck($this->container, $this->config, $seams);
    }
}
