<?php

declare(strict_types = 1);

namespace Tests\Feature\Audit;

use Carbon\CarbonImmutable;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application as FoundationApplication;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\EventContext as AuthenticationContext;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Iam\Audit\AuditRegistrations;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthenticationEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthorizationEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\MfaEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\SsoEventMapper;
use SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesRemoved;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\EventContext as SsoContext;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Fixtures\Providers\RegistersAuditLogWhileBooting;
use Tests\TestCase;

/**
 * Feature tests for this package's registrations with audit-log.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditRegistrations::class)]
#[CoversClass(IamServiceProvider::class)]
final class AuditRegistrationsTest extends TestCase
{
    use PermutesProviderOrder;

    /**
     * The registrations are made before audit-log freezes, in every provider
     * order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheRegistrationsAreMadeBeforeTheFreezeInEveryOrder(array $providers): void
    {
        $this->bootInOrder($providers);

        $this->assertRegistered();
        self::assertTrue($this->catalogue()->isFrozen());
    }

    /**
     * Each member's marker interface has its own mapper, and nothing else is
     * mapped.
     *
     * @return void
     */
    public function testEachMembersInterfaceHasItsMapper(): void
    {
        self::assertSame([
            AuthenticationEvent::class => AuthenticationEventMapper::class,
            MfaEvent::class            => MfaEventMapper::class,
            SsoEvent::class            => SsoEventMapper::class,
            AuthorizationEvent::class  => AuthorizationEventMapper::class,
        ], AuditRegistrations::MAPPERS);

        $registry = $this->registry();

        self::assertSame(AuthenticationEventMapper::class, $registry->mapperFor(SessionCreated::class));
        self::assertSame(MfaEventMapper::class, $registry->mapperFor(RecoveryCodesRemoved::class));
        self::assertSame(SsoEventMapper::class, $registry->mapperFor(ConnectionCreated::class));
        self::assertSame(AuthorizationEventMapper::class, $registry->mapperFor(DecisionEvaluated::class));
        self::assertSame(AuthorizationEventMapper::class, $registry->mapperFor(RoleAssigned::class));
    }

    /**
     * Audit-log's own events are never mapped.
     *
     * @return void
     */
    public function testAuditLogsOwnEventsAreNeverMapped(): void
    {
        self::assertNull($this->registry()->mapperFor(AuditCaptureFailed::class));

        foreach (array_keys(AuditRegistrations::MAPPERS) as $marker) {
            self::assertFalse(is_a(AuditLogEvent::class, $marker, true));
        }
    }

    /**
     * No code is defined twice, and audit-log's own keep their definitions.
     *
     * @return void
     */
    public function testNoCodeIsDefinedTwice(): void
    {
        $codes = [];

        foreach (AuditRegistrations::CODES as $enum) {
            foreach ($enum::cases() as $case) {
                $codes[] = $case->value;
            }
        }

        self::assertSame($codes, array_values(array_unique($codes)));
        self::assertSame([], array_intersect($codes, array_map(static fn (CapturedActivity $code): string => $code->value, CapturedActivity::cases())));

        foreach (CapturedActivity::cases() as $code) {
            self::assertTrue($this->catalogue()->definitionFor(EventCode::of($code))->equals($code->definition()));
        }
    }

    /**
     * A member's event is recorded once, under its code, through the mapping.
     *
     * @return void
     */
    public function testAMembersEventIsRecordedOnce(): void
    {
        $fake    = AuditLog::fake();
        $context = new AuthenticationContext('api', new ClientContext(null, null), sessionId: 'session-1');

        Event::dispatch(new SessionCreated($context));
        Event::dispatch(new ConnectionCreated(new SsoContext(CarbonImmutable::now(), connectionId: 'connection-1')));

        self::assertSame(['session.created', 'sso.connection_created'], array_map(static fn ($record): string => $record->event, $fake->recorded()));
    }

    /**
     * Registering again while the application boots changes nothing.
     *
     * @return void
     */
    #[DefineEnvironment('registerWhileBooting')]
    public function testRegisteringAgainChangesNothing(): void
    {
        $this->assertRegistered();
    }

    /**
     * With the switch off, nothing is mapped and no code defined.
     *
     * @return void
     */
    #[WithConfig(AuditSettings::MAPPERS, false, defer: false)]
    public function testWithTheSwitchOffNothingIsMappedOrDefined(): void
    {
        self::assertNull($this->registry()->mapperFor(SessionCreated::class));

        foreach (AuditRegistrations::CODES as $enum) {
            foreach ($enum::cases() as $case) {
                self::assertFalse($this->catalogue()->isRegistered(EventCode::of($case)));
            }
        }
    }

    /**
     * A provider booted again after boot, already registered, registers nothing
     * more.
     *
     * @return void
     */
    public function testALateRepeatedRegistrationRegistersNothingMore(): void
    {
        $app = $this->application();

        self::assertTrue($app->isBooted());
        self::assertTrue($app->make(AuditRegistrations::REGISTERED));

        AuditRegistrations::register($app, true);

        $this->assertRegistered();
    }

    /**
     * A first registration after boot is refused.
     *
     * @return void
     */
    public function testALateFirstRegistrationIsRefused(): void
    {
        $app = $this->application();

        $app->offsetUnset(AuditRegistrations::REGISTERED);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(
            'laravel-iam was registered after the application booted, when laravel-audit-log takes no registration, '
            . 'so no member event would be recorded; register its provider before the application boots.',
        );

        AuditRegistrations::register($app, true);
    }

    /**
     * An audit-log registered from a later provider's `boot()` is registered
     * with once booted, before it freezes.
     *
     * @return void
     */
    public function testAnAuditLogRegisteredFromALaterProvidersBootIsRegisteredOnceBooted(): void
    {
        $this->bootInOrder([...self::membersWithoutAuditLog(), IamServiceProvider::class, RegistersAuditLogWhileBooting::class]);

        $this->assertRegistered();
        self::assertTrue($this->application()->make(AuditRegistrations::REGISTERED));
        self::assertTrue($this->catalogue()->isFrozen());
        self::assertTrue($this->registry()->hasMappings());
        self::assertSame(1, $this->captureListeners());

        $fake = AuditLog::fake();

        Event::dispatch(new SessionCreated(new AuthenticationContext('api', new ClientContext(null, null), sessionId: 'session-1')));

        self::assertSame(['session.created'], array_map(static fn ($record): string => $record->event, $fake->recorded()));
    }

    /**
     * An audit-log never registered refuses the boot, naming its provider.
     *
     * @return void
     */
    public function testAnAuditLogLeftOutRefusesBoot(): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->expectException(MemberNotRegisteredException::class);
        $this->expectExceptionMessage(AuditLogServiceProvider::class . ' had not registered when the application finished booting');

        $this->bootInOrder([...self::membersWithoutAuditLog(), IamServiceProvider::class]);
    }

    /**
     * Provide the configuration commands that skip the refusal.
     *
     * @return iterable<string, array{list<string>}>
     */
    public static function provideConfigurationCommands(): iterable
    {
        foreach (['config:clear', 'optimize:clear', 'package:discover'] as $command) {
            yield $command => [['artisan', $command]];
        }
    }

    /**
     * A configuration command boots without audit-log, and nothing is
     * registered.
     *
     * @param  list<string>  $arguments
     * @return void
     */
    #[DataProvider('provideConfigurationCommands')]
    public function testAnAuditLogLeftOutIsNotRefusedWhileAConfigurationCommandRuns(array $arguments): void
    {
        $this->withArguments($arguments);

        $this->bootInOrder([...self::membersWithoutAuditLog(), IamServiceProvider::class]);

        self::assertTrue($this->application()->isBooted());
        self::assertFalse($this->application()->bound(AuditRegistrations::REGISTERED));
    }

    /**
     * A normal boot adds one capture listener for the mappings.
     *
     * @return void
     */
    public function testOneCaptureListenerIsAdded(): void
    {
        self::assertSame(1, $this->captureListeners());
    }

    /**
     * With the switch off, the registration is still recorded.
     *
     * @return void
     */
    #[WithConfig(AuditSettings::MAPPERS, false, defer: false)]
    public function testWithTheSwitchOffTheRegistrationIsStillRecorded(): void
    {
        $app = $this->application();

        self::assertTrue($app->bound(AuditRegistrations::REGISTERED));

        AuditRegistrations::register($app, true);

        self::assertNull($this->registry()->mapperFor(SessionCreated::class));
    }

    /**
     * Register the mappers and codes from a booting callback.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function registerWhileBooting(FoundationApplication $app): void
    {
        $app->booting(static function (FoundationApplication $app): void {
            AuditRegistrations::register($app, true);
        });
    }

    /**
     * The registries hold every mapping and definition.
     *
     * @return void
     */
    private function assertRegistered(): void
    {
        foreach (AuditRegistrations::MAPPERS as $marker => $mapper) {
            self::assertSame($mapper, $this->registry()->mapperFor($marker));
        }

        foreach (AuditRegistrations::CODES as $enum) {
            foreach ($enum::cases() as $case) {
                self::assertTrue($this->catalogue()->definitionFor(EventCode::of($case), true)->equals($case->definition()));
            }
        }
    }

    /**
     * Every member's provider but audit-log's, in the tests' default order.
     *
     * @return list<class-string<\Illuminate\Support\ServiceProvider>>
     */
    private static function membersWithoutAuditLog(): array
    {
        return array_values(array_diff(self::MEMBER_PROVIDERS, [AuditLogServiceProvider::class]));
    }

    /**
     * How many of audit-log's capture listeners listen to every event.
     *
     * @return int
     */
    private function captureListeners(): int
    {
        $dispatcher = $this->application()->make('events');

        self::assertInstanceOf(Dispatcher::class, $dispatcher);

        /** @var array<string, list<mixed>> $wildcards */
        $wildcards = (new \ReflectionProperty(Dispatcher::class, 'wildcards'))->getValue($dispatcher);
        $listeners = $wildcards['*'] ?? [];

        return count(array_filter($listeners, static fn (mixed $listener): bool => $listener === CaptureMappedEvent::class));
    }

    /**
     * The booted application.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function application(): FoundationApplication
    {
        $app = $this->app;

        self::assertInstanceOf(FoundationApplication::class, $app);

        return $app;
    }

    /**
     * Audit-log's mapper registry.
     *
     * @return \SineMacula\Laravel\AuditLog\Capture\MapperRegistry
     */
    private function registry(): MapperRegistry
    {
        return $this->application()->make(MapperRegistry::class);
    }

    /**
     * Audit-log's event catalogue.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventCatalogue
     */
    private function catalogue(): EventCatalogue
    {
        return $this->application()->make(EventCatalogue::class);
    }
}
