<?php

declare(strict_types = 1);

namespace Tests\Feature\Mfa;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\PasskeyFactorGateAdapter;
use SineMacula\Laravel\Iam\Mfa\PasskeyGatewayAdapter;
use SineMacula\Laravel\Iam\Mfa\PasskeySeams;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Passkeys\UnavailablePasskeyGateway;
use Tests\TestCase;

/**
 * Feature tests for the seams passkeys become MFA factors through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeySeams::class)]
final class PasskeySeamsTest extends TestCase
{
    /** @var array<class-string, class-string> Each seam, with the adapter bound over it. */
    private const array ADAPTERS = [
        PasskeyGateway::class    => PasskeyGatewayAdapter::class,
        PasskeyFactorGate::class => PasskeyFactorGateAdapter::class,
    ];

    /** @var list<string> The factor types the MFA application offers in the test. */
    private array $offeredTypes = ['totp', 'passkey'];

    /**
     * Both adapters are bound while passkeys are offered.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBothAdaptersAreBoundWhilePasskeysAreOffered(): void
    {
        $this->assertResolvesTo(self::ADAPTERS);
    }

    /**
     * Only the gate is bound while no application offers passkeys.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testOnlyTheGateIsBoundWhileNoApplicationOffersPasskeys(): void
    {
        $this->offeredTypes = ['totp'];

        $this->reloadApplication();

        $this->assertResolvesTo([
            PasskeyGateway::class    => UnavailablePasskeyGateway::class,
            PasskeyFactorGate::class => PasskeyFactorGateAdapter::class,
        ]);
    }

    /**
     * Rows of `[configuration, gateway on, gate on]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool, 2: bool}>
     */
    public static function provideSwitches(): iterable
    {
        yield 'offered by one application' => [['mfa' => ['applications' => ['api' => ['types' => ['totp', 'passkey']]]]], true, true];

        yield 'offered by another application' => [['mfa' => ['applications' => ['api' => ['types' => ['totp']], 'admin' => ['types' => ['passkey']]]]], true, true];

        yield 'offered with the switch off' => [['mfa' => ['applications' => ['api' => ['types' => ['passkey']]]], 'iam' => ['adapters' => ['mfa' => 'off']]], false, false];

        yield 'not offered with the switch off' => [['mfa' => ['applications' => ['api' => ['types' => ['totp']]]], 'iam' => ['adapters' => ['mfa' => 'off']]], false, false];

        yield 'not offered' => [['mfa' => ['applications' => ['api' => ['types' => ['totp', 'sms']]]]], false, true];

        yield 'no applications' => [['mfa' => ['applications' => []]], false, true];

        yield 'applications not a map' => [['mfa' => ['applications' => 'api']], false, true];

        yield 'settings not a map' => [['mfa' => ['applications' => ['api' => 'passkey']]], false, true];

        yield 'types not a list' => [['mfa' => ['applications' => ['api' => ['types' => 'passkey']]]], false, true];

        yield 'no types' => [['mfa' => ['applications' => ['api' => []]]], false, true];

        yield 'a type spelt otherwise' => [['mfa' => ['applications' => ['api' => ['types' => ['Passkey']]]]], false, true];
    }

    /**
     * The gateway needs MFA and passkeys offered, the gate MFA alone.
     *
     * @param  array<string, mixed>  $configuration
     * @param  bool  $offered
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideSwitches')]
    public function testTheGatewayIsOnWhilePasskeysAreOfferedAndTheGateWhileMfaIs(array $configuration, bool $offered, bool $on): void
    {
        $config   = new Repository($configuration);
        $expected = [PasskeyGateway::class => $offered, PasskeyFactorGate::class => $on];

        self::assertSame($offered, PasskeySeams::isOffered($config) && MfaSeams::isOn($config));
        self::assertSame($on, MfaSeams::isOn($config));

        foreach ((new PasskeySeams)->seams($config) as $binding) {
            self::assertSame($expected[$binding->abstract], $binding->on, $binding->abstract);
        }
    }

    /**
     * Rows of `[configuration, application, offered]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string, 2: bool}>
     */
    public static function provideApplicationOffers(): iterable
    {
        yield 'offered by the application' => [['mfa' => ['applications' => ['api' => ['types' => ['totp', 'passkey']]]]], 'api', true];

        yield 'offered by another application only' => [['mfa' => ['applications' => ['api' => ['types' => ['totp']], 'admin' => ['types' => ['passkey']]]]], 'api', false];

        yield 'an application not declared' => [['mfa' => ['applications' => ['admin' => ['types' => ['passkey']]]]], 'api', false];

        yield 'an application named with a dot' => [['mfa' => ['applications' => ['api.v2' => ['types' => ['passkey']]]]], 'api.v2', true];

        yield 'applications not a map' => [['mfa' => ['applications' => 'api']], 'api', false];

        yield 'settings not a map' => [['mfa' => ['applications' => ['api' => 'passkey']]], 'api', false];

        yield 'types not a list' => [['mfa' => ['applications' => ['api' => ['types' => 'passkey']]]], 'api', false];

        yield 'no types' => [['mfa' => ['applications' => ['api' => []]]], 'api', false];

        yield 'a type spelt otherwise' => [['mfa' => ['applications' => ['api' => ['types' => ['Passkey']]]]], 'api', false];
    }

    /**
     * An application offers passkeys while its own types list them.
     *
     * @param  array<string, mixed>  $configuration
     * @param  string  $application
     * @param  bool  $offered
     * @return void
     */
    #[DataProvider('provideApplicationOffers')]
    public function testAnApplicationOffersPasskeysWhileItsOwnTypesListThem(array $configuration, string $application, bool $offered): void
    {
        self::assertSame($offered, PasskeySeams::isOfferedBy(new Repository($configuration), $application));
    }

    /**
     * Both bindings are transient and only the gate is mandatory.
     *
     * @return void
     */
    public function testBothBindingsAreTransientAndTheGateIsMandatory(): void
    {
        $bindings = (new PasskeySeams)->seams(new Repository);

        self::assertSame(self::ADAPTERS, array_combine(
            array_map(static fn (SeamBinding $binding): string => $binding->abstract, $bindings),
            array_map(static fn (SeamBinding $binding): string => $binding->adapter, $bindings),
        ));

        foreach ($bindings as $binding) {
            self::assertSame(Lifetime::TRANSIENT, $binding->lifetime, $binding->abstract);
            self::assertSame($binding->abstract === PasskeyFactorGate::class, $binding->isMandatory(), $binding->abstract);
        }
    }

    /**
     * Offer the factor types the test names.
     *
     * @return list<string>
     */
    #[\Override]
    protected function mfaTypes(): array
    {
        return $this->offeredTypes;
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
