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
use SineMacula\Laravel\Authentication\External\NoExternalLinks;
use SineMacula\Laravel\Authentication\Passkeys\NoPasskeyFactors;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Iam\Contracts\TenantTree;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Mfa\ContextSeams;
use SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker;
use SineMacula\Laravel\Mfa\Requirements\NoActiveTenant;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Enforcement\OwnTenantInheritance;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Bindings\Adapter;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;
use Tests\Fixtures\Bindings\DeclaredSeams;
use Tests\Fixtures\Checks\ExtensibleDefault;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\TestCase;

/**
 * Feature tests for the check that every mandatory seam is bound off its
 * member's permissive or inert default (IAM-10.2): each mandatory seam and the
 * condition it is mandatory under, read from the binding rule's own rows as the
 * configuration and the container stand when the check runs.
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
     * The application the package binds passes: every mandatory seam holds this
     * package's adapter, SSO's in use or not.
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
     * Rows of `[seam, member default]` for the seams that are always mandatory.
     *
     * @return iterable<string, array{class-string, class-string}>
     */
    public static function alwaysMandatory(): iterable
    {
        yield 'SSO\'s session revocation' => [SessionRevocation::class, NoSessionRevocation::class];
        yield 'MFA\'s session revoker' => [SessionRevoker::class, GenerationSessionRevoker::class];
        yield 'the passkey factor gate' => [PasskeyFactorGate::class, NoPasskeyFactors::class];
    }

    /**
     * A seam that is always mandatory, bound back to its member's default,
     * fails, naming the seam and the default.
     *
     * @param  class-string  $seam
     * @param  class-string  $default
     * @return void
     */
    #[DataProvider('alwaysMandatory')]
    public function testASeamLeftOnItsMembersDefaultFails(string $seam, string $default): void
    {
        $this->app?->bind($seam, $default);

        $problems = self::problems($this->check()->checks());

        self::assertCount(1, $problems);
        self::assertStringContainsString($seam . ' is still bound to ' . $default, $problems[0]);
    }

    /**
     * With this package's SSO capability off, the application binds SSO's seams
     * itself, under the same mandate: SSO's session revocation, left on SSO's
     * default, fails.
     *
     * @return void
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testAMandatorySeamIsCheckedWithItsCapabilityOff(): void
    {
        $problem = SessionRevocation::class . ' is still bound to ' . NoSessionRevocation::class
            . ', its member\'s permissive or inert default; bind ' . SessionRevocationAdapter::class . ', or an implementation of your own, to it.';

        self::assertSame([$problem], self::problems($this->check()->checks()));
    }

    /**
     * A member default something has already resolved, held as the shared
     * instance, is read from the instance and fails as well.
     *
     * @return void
     */
    public function testAResolvedMemberDefaultFails(): void
    {
        $this->app?->singleton(SessionRevocation::class, NoSessionRevocation::class);
        $this->app?->make(SessionRevocation::class);

        self::assertStringContainsString(SessionRevocation::class . ' is still bound to ' . NoSessionRevocation::class, self::problems($this->check()->checks())[0]);
    }

    /**
     * A seam bound to the application's own implementation passes, by class
     * name or as an instance.
     *
     * @return void
     */
    public function testTheApplicationsOwnBindingPasses(): void
    {
        $implementation = new class {};

        $this->app?->bind(SessionRevocation::class, $implementation::class);
        $this->app?->instance(SessionRevoker::class, $implementation);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * A seam bound to an anonymous implementation of the application's own
     * passes, as an instance or by its class name, though the anonymous class
     * is named after the member's contract it implements; with SSO in use, the
     * seams the check of SSO's side holds are read alike.
     *
     * @return void
     */
    public function testAnAnonymousImplementationOfTheApplicationsOwnPasses(): void
    {
        $revocation = new class implements SessionRevocation {
            /**
             * Revoke the sessions in the scope.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void {}
        };

        $this->app?->instance(SessionRevocation::class, $revocation);

        self::assertSame([], self::problems($this->check()->checks()));

        $this->app?->offsetUnset(SessionRevocation::class);
        $this->app?->bind(SessionRevocation::class, $revocation::class);

        self::assertSame([], self::problems($this->check()->checks()));

        $this->useSso();

        self::assertSame([], self::problems($this->mandates()));
    }

    /**
     * A seam bound to an anonymous subclass of its member's default fails, as
     * an instance or by its class name, naming the default it extends.
     *
     * @return void
     */
    public function testAnAnonymousSubclassOfAMembersDefaultFails(): void
    {
        $subclass = new class extends ExtensibleDefault {};
        $checks   = $this->check()->checksFor(new DeclaredSeams(
            new SeamBinding(PlainSeam::class, Adapter::class, [ExtensibleDefault::class], mandatory: true),
            new SeamBinding(SharedSeam::class, Adapter::class, [ExtensibleDefault::class], mandatory: true),
        ));

        $this->app?->instance(PlainSeam::class, $subclass);
        $this->app?->bind(SharedSeam::class, $subclass::class);

        $problems = self::problems($checks);

        self::assertCount(2, $problems);
        self::assertStringContainsString(PlainSeam::class . ' is still bound to ' . ExtensibleDefault::class . ',', $problems[0]);
        self::assertStringContainsString(SharedSeam::class . ' is still bound to ' . ExtensibleDefault::class . ',', $problems[1]);
    }

    /**
     * A seam bound through a closure of the application's own fails: what it
     * returns cannot be read without building it, and the check takes nothing
     * on trust, so the seam is bound by class name or as an instance instead.
     * One something has already resolved is read from its instance.
     *
     * @return void
     */
    public function testAnApplicationsClosureFails(): void
    {
        $this->app?->bind(SessionRevoker::class, static fn (): object => new \stdClass);

        $problem = SessionRevoker::class . ' is bound through a closure, whose implementation cannot be read without building it; bind '
            . SessionRevokerAdapter::class . ', or an implementation of your own, to it by class name or as an instance.';

        self::assertSame([$problem], self::problems($this->check()->checks()));

        $this->app?->singleton(SessionRevoker::class, static fn (): object => new class {});
        $this->app?->make(SessionRevoker::class);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * A seam bound to a class of a member's own that is not among the row's
     * defaults fails all the same, as a member's renamed default would: the
     * external identity links bound to SSO's `NoLinks`.
     *
     * @return void
     */
    public function testAnyClassOfAMembersOwnFails(): void
    {
        $this->useSso();

        $this->app?->bind(ExternalIdentityLinks::class, NoLinks::class);

        self::assertStringContainsString(ExternalIdentityLinks::class . ' is still bound to ' . NoLinks::class, self::problems($this->mandates())[0]);
    }

    /**
     * A mandatory seam left unbound fails, naming the adapter to bind.
     *
     * @return void
     */
    public function testAnUnboundMandatorySeamFails(): void
    {
        $this->useSso();

        $this->app?->offsetUnset(Linker::class);

        $problem = Linker::class . ' is unbound; bind ' . LinkStore::class . ', or an implementation of your own, to it.';

        self::assertSame([$problem], self::problems($this->mandates()));

        $this->app?->offsetUnset(SessionRevoker::class);

        self::assertStringStartsWith(SessionRevoker::class . ' is unbound', self::problems($this->check()->checks())[0]);
    }

    /**
     * While SSO is in use, the seams this package's check of SSO's side holds
     * are left to it, so each is reported once: the bridge reports SSO's linker
     * left on its default, and this check does not.
     *
     * @return void
     */
    public function testTheSeamsSsosCheckHoldsAreLeftToIt(): void
    {
        $this->useSso();

        $this->app?->bind(Linker::class, NoLinks::class);

        self::assertSame([], self::problems($this->check()->checks()));

        $bridge = $this->app?->make(SsoBridgeCheck::class);

        assert($bridge instanceof SsoBridgeCheck);

        self::assertStringContainsString(Linker::class . ' is still bound to ' . NoLinks::class, self::problems($bridge->checks())[0]);
    }

    /**
     * The links and the link store are mandatory only while SSO is in use: left
     * on their defaults, they pass while it is not, and fail once a protocol is
     * switched on, or its switch is malformed. The linker is SSO's own link
     * store, which passes.
     *
     * @return void
     */
    public function testTheLinksAreMandatoryWhileSsoIsInUse(): void
    {
        $this->app?->bind(ExternalIdentityLinks::class, NoExternalLinks::class);
        $this->app?->bind(Linker::class, NoLinks::class);

        self::assertSame([], self::problems($this->check()->checks()));

        $this->app?->make('config')->set('sso.features.oidc', 'sometimes');

        $problems = self::problems($this->mandates());

        self::assertCount(2, $problems);
        self::assertStringContainsString(ExternalIdentityLinks::class, $problems[0]);
        self::assertStringContainsString(Linker::class, $problems[1]);
    }

    /**
     * Rows of `[seam, member default]` for the seams mandatory while SSO's
     * enforcement or a tenant MFA requirement is on.
     *
     * @return iterable<string, array{class-string, class-string}>
     */
    public static function mandatoryUnderTenantRules(): iterable
    {
        yield 'the re-authentication sessions' => [ReauthenticationSessions::class, NoReauthenticationSessions::class];
        yield 'the tenant authentication policy' => [TenantAuthenticationPolicy::class, RequireNothingOfTenants::class];
        yield 'MFA\'s active tenant resolver' => [ActiveTenantResolver::class, NoActiveTenant::class];
    }

    /**
     * Rows of how a tenant's rule is turned on: SSO's enforcement, or MFA's
     * tenant requirement bound.
     *
     * @return iterable<string, array{\Closure(\Illuminate\Contracts\Foundation\Application): void}>
     */
    public static function tenantRules(): iterable
    {
        yield 'enforcement' => [static function (Application $app): void {
            $app->make('config')->set(TenancySeams::ENFORCEMENT, true);
        }];
        yield 'a requirement bound' => [static function (Application $app): void {
            $app->bind(TenantRequirement::class, ScriptedTenantRequirement::class);
        }];
    }

    /**
     * Every combination of a seam mandatory under a tenant's rule and the way
     * the rule is turned on.
     *
     * @return iterable<string, array{class-string, class-string, \Closure(\Illuminate\Contracts\Foundation\Application): void}>
     */
    public static function seamsUnderEachRule(): iterable
    {
        foreach (self::mandatoryUnderTenantRules() as $seam => [$abstract, $default]) {

            foreach (self::tenantRules() as $rule => [$turnOn]) {
                yield $seam . ' under ' . $rule => [$abstract, $default, $turnOn];
            }
        }
    }

    /**
     * The re-authentication sessions, the tenant authentication policy and
     * MFA's active tenant resolver pass on their defaults until SSO's
     * enforcement or a tenant MFA requirement is on, and fail from then.
     *
     * @param  class-string  $seam
     * @param  class-string  $default
     * @param  \Closure(\Illuminate\Contracts\Foundation\Application): void  $turnOn
     * @return void
     */
    #[DataProvider('seamsUnderEachRule')]
    public function testASeamIsMandatoryWhileATenantsRuleIsOn(string $seam, string $default, \Closure $turnOn): void
    {
        $this->app?->bind($seam, $default);

        self::assertSame([], self::problems($this->check()->checks()));

        $turnOn($this->app ?? self::fail('The application has not booted.'));

        $problems = self::problems($this->check()->checks());

        self::assertCount(1, $problems);
        self::assertStringContainsString($seam . ' is still bound to ' . $default, $problems[0]);
    }

    /**
     * The enforcement inheritance is mandatory while the application has a
     * tenant tree, named or bound, and SSO's enforcement is on: neither alone
     * makes it so.
     *
     * @return void
     */
    public function testTheInheritanceIsMandatoryWhileATreeAndEnforcementAreOn(): void
    {
        $config = $this->app?->make('config');

        $this->app?->bind(EnforcementInheritance::class, OwnTenantInheritance::class);

        $config?->set('iam.tenancy.tree', FakeTenantTree::class);

        self::assertSame([], self::problems($this->check()->checks()));

        $config?->set('iam.tenancy.tree', null);
        $config?->set(TenancySeams::ENFORCEMENT, 'true');

        self::assertSame([], self::problems($this->check()->checks()));

        $this->app?->bind(TenantTree::class, FakeTenantTree::class);

        self::assertStringContainsString(EnforcementInheritance::class . ' is still bound to ' . OwnTenantInheritance::class, self::problems($this->check()->checks())[0]);
    }

    /**
     * A seam the binding rule kept with the application's binding is reported
     * as a note, which is no problem; with no outcome kept, there is none.
     *
     * @return void
     */
    public function testEachSeamTheRuleKeptIsNoted(): void
    {
        self::assertSame([], self::notes($this->check()->checks()));

        $this->app?->instance(BindingOutcome::class, new BindingOutcome([], [SessionRevocation::class]));

        self::assertSame([SessionRevocation::class . ' keeps the application\'s binding, not this package\'s adapter.'], self::notes($this->check()->checks()));

        $this->app?->offsetUnset(BindingOutcome::class);

        self::assertSame([], self::notes($this->check()->checks()));
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
     * Put SSO in use.
     *
     * @return void
     */
    private function useSso(): void
    {
        $this->app?->make('config')->set('sso.features.saml2', true);
    }

    /**
     * The checks of every mandatory seam every capability declares now, those
     * `sso:check` holds included.
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

        assert($check instanceof MandatorySeamsCheck);

        return $check;
    }
}
