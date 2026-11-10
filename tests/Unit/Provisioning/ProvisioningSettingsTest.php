<?php

declare(strict_types = 1);

namespace Tests\Unit\Provisioning;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Bindings\ConfiguredImplementations;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Iam\Exceptions\ProvisionerMisconfiguredException;
use SineMacula\Laravel\Iam\Provisioning\ProvisioningSettings;
use SineMacula\Laravel\Iam\Testing\FakeProvisioner;
use Tests\Fixtures\Provisioning\ProvisionsPeople;
use Tests\Fixtures\Sso\PlainIdentity;

/**
 * Unit tests for whether provisioning is on and which provisioner it asks
 * (IAM-7.1): the application's binding wins over the class it names (IAM-8.4),
 * a class named is built, neither turns provisioning off, the provisioner is
 * the one bound when asked, and a class named that is no provisioner, a value
 * that is no class name, or a binding that resolves to none, fails closed
 * rather than turn provisioning off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProvisioningSettings::class)]
#[CoversClass(ConfiguredImplementations::class)]
#[CoversClass(ProvisionerMisconfiguredException::class)]
final class ProvisioningSettingsTest extends TestCase
{
    /** @var \Illuminate\Container\Container The container the provisioner is bound and built in. */
    private Container $container;

    /** @var \Illuminate\Config\Repository The configuration naming the provisioner. */
    private Repository $config;

    /**
     * Start each test with an empty container and the shipped provisioning
     * configuration.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
        $this->config    = new Repository(['iam' => ['provisioning' => ['provisioner' => null]]]);
    }

    /**
     * The key is the shipped configuration's.
     *
     * @return void
     */
    public function testTheKeyIsTheShippedConfigurations(): void
    {
        $shipped = require dirname(__DIR__, 3) . '/config/iam.php';

        self::assertIsArray($shipped);
        self::assertSame('iam.provisioning.provisioner', ProvisioningSettings::KEY);
        self::assertSame(['provisioner' => null, 'groups' => ['mapping' => null, 'map' => [], 'resync' => null]], $shipped['provisioning']);
    }

    /**
     * Rows of `[value]` that name no provisioner: nothing, and blank text.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideNoProvisioners(): iterable
    {
        yield 'nothing' => [null];

        yield 'empty text' => [''];

        yield 'blank text' => [" \t "];
    }

    /**
     * With no provisioner bound, and nothing or blank text named, provisioning
     * is off.
     *
     * @param  ?string  $value
     * @return void
     */
    #[DataProvider('provideNoProvisioners')]
    public function testWithNoProvisionerProvisioningIsOff(?string $value): void
    {
        $this->config->set(ProvisioningSettings::KEY, $value);

        self::assertNull($this->settings()->provisioner());
    }

    /**
     * The class the configuration names is built.
     *
     * @return void
     */
    public function testTheClassNamedIsBuilt(): void
    {
        $this->config->set(ProvisioningSettings::KEY, ProvisionsPeople::class);

        $provisioner = new ProvisionsPeople;

        $this->container->instance(ProvisionsPeople::class, $provisioner);

        self::assertSame($provisioner, $this->settings()->provisioner());
    }

    /**
     * The application's binding of the contract wins over the class named.
     *
     * @return void
     */
    public function testTheApplicationsBindingWinsOverTheClassNamed(): void
    {
        $this->config->set(ProvisioningSettings::KEY, ProvisionsPeople::class);

        $fake = FakeProvisioner::fake(static fn (): Identity => new PlainIdentity([]), null, $this->container);

        self::assertSame($fake, $this->settings()->provisioner());
    }

    /**
     * The provisioner is the one bound when it is asked for, so one bound after
     * the settings were built is the one answered.
     *
     * @return void
     */
    public function testTheProvisionerIsTheOneBoundWhenAsked(): void
    {
        $settings = $this->settings();

        self::assertNull($settings->provisioner());

        $fake = FakeProvisioner::fake(static fn (): Identity => new PlainIdentity([]), null, $this->container);

        self::assertSame($fake, $settings->provisioner());
    }

    /**
     * Rows of `[class named]` that are no provisioner: a class implementing
     * another contract, and a class that does not exist.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNoProvisionerClasses(): iterable
    {
        yield 'a class that is no provisioner' => [PlainIdentity::class];

        yield 'a class that does not exist' => ['App\Provisioning\Missing'];
    }

    /**
     * A class named that is no provisioner fails closed, naming the key and the
     * class.
     *
     * @param  string  $named
     * @return void
     */
    #[DataProvider('provideNoProvisionerClasses')]
    public function testAClassNamedThatIsNoProvisionerFailsClosed(string $named): void
    {
        $this->config->set(ProvisioningSettings::KEY, $named);

        $this->expectException(ProvisionerMisconfiguredException::class);
        $this->expectExceptionMessage(sprintf(
            'iam.provisioning.provisioner names [%s], which is not a class implementing %s, so no unlinked result can be provisioned.',
            $named,
            Provisioner::class,
        ));

        $this->settings()->provisioner();
    }

    /**
     * Rows of `[value, type]` that are no class name at all.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideValuesThatAreNoClassName(): iterable
    {
        yield 'true' => [true, 'bool'];

        yield 'false' => [false, 'bool'];

        yield 'a number' => [1, 'int'];

        yield 'an array' => [[ProvisionsPeople::class], 'array'];
    }

    /**
     * A value that is no class name fails closed, naming its type, never the
     * value.
     *
     * @param  mixed  $value
     * @param  string  $type
     * @return void
     */
    #[DataProvider('provideValuesThatAreNoClassName')]
    public function testAValueThatIsNoClassNameFailsClosed(mixed $value, string $type): void
    {
        $this->config->set(ProvisioningSettings::KEY, $value);

        $this->expectException(ProvisionerMisconfiguredException::class);
        $this->expectExceptionMessage(sprintf(
            'iam.provisioning.provisioner holds a value of type [%s], which names no class implementing %s, so no unlinked result can be provisioned:'
            . ' name the class, or leave it null to turn provisioning off.',
            $type,
            Provisioner::class,
        ));

        $this->settings()->provisioner();
    }

    /**
     * A binding of the contract that resolves to no provisioner fails closed,
     * naming the binding.
     *
     * @return void
     */
    public function testABindingThatResolvesToNoProvisionerFailsClosed(): void
    {
        $this->container->bind(Provisioner::class, static fn (): object => new \stdClass);

        $this->expectException(ProvisionerMisconfiguredException::class);
        $this->expectExceptionMessage(sprintf(
            'The container binding of %s resolves to [stdClass], which is no provisioner, so no unlinked result can be provisioned: bind it to a class implementing %s.',
            Provisioner::class,
            Provisioner::class,
        ));

        $this->settings()->provisioner();
    }

    /**
     * A binding of the class named that resolves to no provisioner fails
     * closed, naming that binding.
     *
     * @return void
     */
    public function testABindingOfTheClassNamedThatResolvesToNoProvisionerFailsClosed(): void
    {
        $this->config->set(ProvisioningSettings::KEY, ProvisionsPeople::class);
        $this->container->bind(ProvisionsPeople::class, static fn (): object => new \stdClass);

        $this->expectException(ProvisionerMisconfiguredException::class);
        $this->expectExceptionMessage(sprintf('The container binding of %s resolves to [stdClass]', ProvisionsPeople::class));

        $this->settings()->provisioner();
    }

    /**
     * The settings under test, over the container and the configuration.
     *
     * @return \SineMacula\Laravel\Iam\Provisioning\ProvisioningSettings
     */
    private function settings(): ProvisioningSettings
    {
        return new ProvisioningSettings($this->container, $this->config);
    }
}
