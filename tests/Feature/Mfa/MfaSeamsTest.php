<?php

declare(strict_types = 1);

namespace Tests\Feature\Mfa;

use Illuminate\Config\Repository;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck as AuthenticationRequirementCheck;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Mfa\AdditionalFactorPolicyAdapter;
use SineMacula\Laravel\Iam\Mfa\FactorChangeGateAdapter;
use SineMacula\Laravel\Iam\Mfa\FirstFactorResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\FreshnessGateAdapter;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Mfa\ReauthenticatorAdapter;
use SineMacula\Laravel\Iam\Mfa\RequirementCheckAdapter;
use SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter;
use SineMacula\Laravel\Iam\Mfa\SessionTransitionAdapter;
use SineMacula\Laravel\Iam\Mfa\StepUpAdapter;
use SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactorResolver;
use SineMacula\Laravel\Mfa\Context\NoPendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Http\MiddlewareSessionTransition;
use SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\ProofBindings;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFactorChangeGate;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Seams\RefusingReauthenticator;
use Tests\Concerns\PermutesProviderOrder;
use Tests\TestCase;

/**
 * Feature tests for the seams `laravel-authentication` and MFA join through:
 * every adapter replaces its member's default, MFA's closure-bound proof store
 * included, in every provider order; an application's own binding is kept or
 * wins as the binding rule says (IAM-8.4); and the capability's switch turns
 * every binding off at once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaSeams::class)]
final class MfaSeamsTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var array<class-string, class-string> Each seam, with the adapter bound over it. */
    private const array ADAPTERS = [
        AdditionalFactorPolicy::class         => AdditionalFactorPolicyAdapter::class,
        AuthenticationRequirementCheck::class => RequirementCheckAdapter::class,
        PendingSessionResolver::class         => PendingSessionResolverAdapter::class,
        PendingCompletion::class              => PendingCompletionAdapter::class,
        StepUp::class                         => StepUpAdapter::class,
        Reauthenticator::class                => ReauthenticatorAdapter::class,
        FreshnessGate::class                  => FreshnessGateAdapter::class,
        FactorChangeGate::class               => FactorChangeGateAdapter::class,
        SessionRevoker::class                 => SessionRevokerAdapter::class,
        SessionTransition::class              => SessionTransitionAdapter::class,
        ProofStore::class                     => ProofStoreAdapter::class,
        FirstFactorResolver::class            => FirstFactorResolverAdapter::class,
    ];

    /** @var array<class-string, class-string> Each seam, with the class its member's own default resolves to. */
    private const array MEMBER_DEFAULTS = [
        AdditionalFactorPolicy::class         => NeverRequireAdditionalFactor::class,
        AuthenticationRequirementCheck::class => MeetNoRequirement::class,
        PendingSessionResolver::class         => NoPendingSessionResolver::class,
        PendingCompletion::class              => ProofStoreCompletion::class,
        StepUp::class                         => ProofStoreCompletion::class,
        Reauthenticator::class                => RefusingReauthenticator::class,
        FreshnessGate::class                  => ConfiguredFreshnessGate::class,
        FactorChangeGate::class               => ConfiguredFactorChangeGate::class,
        SessionRevoker::class                 => GenerationSessionRevoker::class,
        SessionTransition::class              => MiddlewareSessionTransition::class,
        ProofStore::class                     => SessionProofStore::class,
        FirstFactorResolver::class            => DeclaredFirstFactorResolver::class,
    ];

    /**
     * Every adapter is bound over its member's default, MFA's proof store
     * (bound with a closure its proof bindings declare) included, in every
     * provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers);

        $this->assertResolvesTo(self::ADAPTERS);
        $this->assertOutcome(array_keys(self::ADAPTERS), []);
    }

    /**
     * An application binding made before any provider registers is kept over
     * every seam, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeBeforeAnyProviderRegistersIsKept(array $providers): void
    {
        [$bindings, $instances] = self::applicationBindings();

        $this->bootInOrder($providers, before: $bindings);

        $this->assertResolvesToInstances($instances);
        $this->assertOutcome([], array_keys(self::ADAPTERS));
    }

    /**
     * An application binding made once every provider has registered replaces
     * every adapter, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins(array $providers): void
    {
        [$bindings, $instances] = self::applicationBindings();

        $this->bootInOrder($providers, after: $bindings);

        $this->assertResolvesToInstances($instances);
        $this->assertOutcome(array_keys(self::ADAPTERS), []);
    }

    /**
     * With the switch off nothing is bound, and every member keeps its own
     * default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    public function testTheSwitchOffBindsNothing(): void
    {
        $this->assertResolvesTo(self::MEMBER_DEFAULTS);
        $this->assertOutcome([], []);
    }

    /**
     * Rows of `[value, on]`: the switch's value, and whether it leaves the
     * bindings on.
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
     * The switch is read leniently: `false`, as a boolean or as text, `0`,
     * `off` and `no` turn every binding off; anything else leaves them on.
     *
     * @param  mixed  $value
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideSwitchValues')]
    public function testTheSwitchIsReadLeniently(mixed $value, bool $on): void
    {
        $config = new Repository(['iam' => ['adapters' => ['mfa' => $value]]]);

        foreach ((new MfaSeams)->seams($config) as $binding) {

            self::assertNotNull($binding->appliesWhen);
            self::assertSame($on, ($binding->appliesWhen)($config), $binding->abstract);
        }
    }

    /**
     * Every binding is transient over the member's own default, and only
     * revocation on factor removal and reset is mandatory (IAM-3.7).
     *
     * @return void
     */
    public function testEveryBindingIsTransientOverItsMembersDefault(): void
    {
        $bindings = (new MfaSeams)->seams(new Repository);

        self::assertSame(self::ADAPTERS, array_combine(
            array_map(static fn (SeamBinding $binding): string => $binding->abstract, $bindings),
            array_map(static fn (SeamBinding $binding): string => $binding->adapter, $bindings),
        ));

        foreach ($bindings as $binding) {

            self::assertSame(Lifetime::TRANSIENT, $binding->lifetime, $binding->abstract);
            self::assertSame($binding->abstract === SessionRevoker::class, $binding->mandatory, $binding->abstract);

            $default = $binding->abstract === ProofStore::class ? ProofBindings::class : self::MEMBER_DEFAULTS[$binding->abstract];

            self::assertSame([$default], $binding->memberDefaults, $binding->abstract);
        }
    }

    /**
     * The application's own binding of every seam, each a closure this test
     * declares returning its own instance, with those instances.
     *
     * @return array{0: array<string, \Closure(): object>, 1: array<string, object>}
     */
    private static function applicationBindings(): array
    {
        $bindings  = [];
        $instances = [];

        foreach (array_keys(self::ADAPTERS) as $abstract) {

            $instance = \Mockery::mock($abstract);

            $instances[$abstract] = $instance;
            $bindings[$abstract]  = static fn (): object => $instance;
        }

        return [$bindings, $instances];
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

    /**
     * Assert each seam resolves to the given instance.
     *
     * @param  array<string, object>  $expected
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertResolvesToInstances(array $expected): void
    {
        foreach ($expected as $abstract => $instance) {
            self::assertSame($instance, $this->app?->make($abstract), $abstract);
        }
    }

    /**
     * Assert the binding rule bound and kept exactly the given seams, in the
     * order they are declared.
     *
     * @param  list<string>  $bound
     * @param  list<string>  $kept
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertOutcome(array $bound, array $kept): void
    {
        $outcome = $this->app?->make(BindingOutcome::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertSame($bound, $outcome->bound);
        self::assertSame($kept, $outcome->kept);
    }
}
