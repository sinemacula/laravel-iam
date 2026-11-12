<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use Illuminate\Contracts\Foundation\Application;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Mfa\ContextSeams;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the check that every mandatory seam is bound off its
 * member's default (IAM-10.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MandatorySeamsCheck::class)]
#[CoversClass(SsoSeams::class)]
#[CoversClass(ContextSeams::class)]
#[CoversClass(TenancySeams::class)]
final class MandatorySeamsCheckTest extends TestCase
{
    use RunsChecks;

    /**
     * The adapters this package binds pass, SSO in use or not.
     *
     * @return void
     */
    public function testTheBindingsThisPackageMakesPass(): void
    {
        self::assertSame([], self::problems($this->check()->checks()));

        $this->useSso();

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * Every seam that is always mandatory fails on its member's default, with
     * the capabilities off.
     *
     * @return void
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testTheMembersDefaultsFail(): void
    {
        $problem = SessionRevocation::class . ' is still bound to its member\'s permissive or inert default; bind '
            . SessionRevocationAdapter::class . ', or an implementation of your own, to it.';

        $problems = self::problems($this->check()->checks());

        self::assertCount(3, $problems);
        self::assertStringStartsWith(SessionRevoker::class . ' is still bound', $problems[0]);
        self::assertStringStartsWith(PasskeyFactorGate::class . ' is still bound', $problems[1]);
        self::assertSame($problem, $problems[2]);
    }

    /**
     * A member's default something has already resolved still fails.
     *
     * @return void
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    public function testAResolvedMembersDefaultFails(): void
    {
        $this->app?->make(PasskeyFactorGate::class);

        self::assertStringStartsWith(PasskeyFactorGate::class . ' is still bound', self::problems($this->check()->checks())[1]);
    }

    /**
     * The application's own binding passes, as a class, an instance or a
     * closure.
     *
     * @return void
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testTheApplicationsOwnBindingPasses(): void
    {
        $implementation = new class {};

        $this->app?->bind(SessionRevocation::class, $implementation::class);
        $this->app?->instance(SessionRevoker::class, $implementation);
        $this->app?->bind(PasskeyFactorGate::class, static fn (): object => $implementation);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * MFA's own default bound back by the application is still MFA's default,
     * as MFA says.
     *
     * @return void
     */
    public function testMfasDefaultBoundByNameFails(): void
    {
        $this->app?->bind(SessionRevoker::class, GenerationSessionRevoker::class);

        self::assertStringStartsWith(SessionRevoker::class . ' is still bound', self::problems($this->check()->checks())[0]);
    }

    /**
     * An unbound mandatory seam fails, naming the adapter to bind.
     *
     * @return void
     */
    public function testAnUnboundMandatorySeamFails(): void
    {
        $this->useSso();

        $this->app?->offsetUnset(Linker::class);

        $problem = Linker::class . ' is unbound; bind ' . LinkStore::class . ', or an implementation of your own, to it.';

        self::assertSame([$problem], self::problems($this->mandates()));
    }

    /**
     * While SSO is in use, the seams the check of SSO's side holds are left to
     * it.
     *
     * @return void
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testTheSeamsSsosCheckHoldsAreLeftToIt(): void
    {
        $this->useSso();

        self::assertSame([], self::problems($this->check()->checks()));

        $bridge = $this->app?->make(SsoBridgeCheck::class);

        self::assertInstanceOf(SsoBridgeCheck::class, $bridge);
        self::assertStringStartsWith(SessionRevocation::class . ' is still bound', self::problems($bridge->checks())[0]);
    }

    /**
     * The links and the linker are mandatory only while SSO is in use.
     *
     * @return void
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testTheLinksAreMandatoryWhileSsoIsInUse(): void
    {
        $this->app?->instance(SessionRevocation::class, new NoSessionRevocation);

        self::assertSame([], self::problems($this->mandates()));

        $this->app?->make('config')->set('sso.features.oidc', 'sometimes');

        $problems = self::problems($this->mandates());

        self::assertCount(2, $problems);
        self::assertStringStartsWith(ExternalIdentityLinks::class, $problems[0]);
        self::assertStringStartsWith(Linker::class, $problems[1]);
    }

    /**
     * Rows of how a tenant's rule is turned on: SSO's enforcement, or MFA's
     * tenant requirement bound.
     *
     * @return iterable<string, array{\Closure(\Illuminate\Contracts\Foundation\Application): void}>
     */
    public static function provideTenantRules(): iterable
    {
        yield 'enforcement' => [static function (Application $app): void {
            $app->make('config')->set(TenancySeams::ENFORCEMENT, true);
        }];

        yield 'a requirement bound' => [static function (Application $app): void {
            $app->bind(TenantRequirement::class, ScriptedTenantRequirement::class);
        }];
    }

    /**
     * The re-authentication sessions, the tenant authentication policy and
     * MFA's active tenant resolver are mandatory once a tenant's rule is on.
     *
     * @param  \Closure(\Illuminate\Contracts\Foundation\Application): void  $turnOn
     * @return void
     */
    #[DataProvider('provideTenantRules')]
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testTheTenantSeamsAreMandatoryWhileATenantsRuleIsOn(\Closure $turnOn): void
    {
        $seams = [ReauthenticationSessions::class, TenantAuthenticationPolicy::class, ActiveTenantResolver::class];

        self::assertSame([], array_values(array_filter(self::problems($this->mandates()), static fn (string $problem): bool => self::names($problem, $seams))));

        $turnOn($this->app ?? self::fail('The application has not booted.'));

        $refused = array_values(array_filter(self::problems($this->mandates()), static fn (string $problem): bool => self::names($problem, $seams)));

        self::assertCount(3, $refused);
    }

    /**
     * The enforcement inheritance is mandatory while enforcing over a tenant
     * tree, and neither alone makes it so.
     *
     * @return void
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testTheInheritanceIsMandatoryWhileEnforcingOverATree(): void
    {
        $inheritance = static fn (string $problem): bool => str_starts_with($problem, EnforcementInheritance::class);

        $this->app?->instance(TenantTree::class, new StoredTenantTree);

        self::assertSame([], array_filter(self::problems($this->mandates()), $inheritance));

        $this->app?->instance(TenantTree::class, new FlatTenantTree);
        $this->app?->make('config')->set(TenancySeams::ENFORCEMENT, 'true');

        self::assertSame([], array_filter(self::problems($this->mandates()), $inheritance));

        $this->app?->instance(TenantTree::class, new StoredTenantTree);

        self::assertCount(1, array_filter(self::problems($this->mandates()), $inheritance));
    }

    /**
     * The check always applies, under the subject `seams`.
     *
     * @return void
     */
    public function testItAlwaysAppliesUnderItsSubject(): void
    {
        self::assertTrue($this->check()->applies());
        self::assertSame('seams', $this->check()->subject());
    }

    /**
     * Whether the problem names one of the seams.
     *
     * @param  string  $problem
     * @param  list<string>  $seams
     * @return bool
     */
    private static function names(string $problem, array $seams): bool
    {
        return array_filter($seams, static fn (string $seam): bool => str_starts_with($problem, $seam . ' ')) !== [];
    }

    /**
     * Put SSO in use.
     *
     * @return void
     */
    private function useSso(): void
    {
        $this->app?->make('config')->set('sso.features.saml2', true);
    }

    /**
     * The checks of every mandatory seam, those `sso:check` holds included.
     *
     * @return list<\Closure(): mixed>
     */
    private function mandates(): array
    {
        $app          = $this->app ?? self::fail('The application has not booted.');
        $capabilities = array_map(static fn (string $provider): ProvidesSeams => $app->make($provider), IamServiceProvider::seamProviders());

        return $this->check()->checksFor(...$capabilities);
    }

    /**
     * The check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck
     */
    private function check(): MandatorySeamsCheck
    {
        $check = $this->app?->make(MandatorySeamsCheck::class);

        self::assertInstanceOf(MandatorySeamsCheck::class, $check);

        return $check;
    }
}
