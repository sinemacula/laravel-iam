<?php

declare(strict_types = 1);

namespace Tests\Feature\Audit;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\IntegrityAlarm;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use SineMacula\Laravel\Authentication\Events\EventContext as AuthenticationContext;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Audit\OperationalAlerts;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use Tests\Concerns\RunsInOctaneSandboxes;
use Tests\Fixtures\Audit\AlertInbox;
use Tests\Fixtures\Audit\HandlesAlerts;
use Tests\Fixtures\Audit\HearsNoAlerts;
use Tests\Fixtures\Audit\InvokedOnAlerts;
use Tests\Fixtures\Sso\PlainIdentity;
use Tests\TestCase;

/**
 * Feature tests for the operational events offered to the application's
 * alerting (IAM-9.8): one listener of each of audit-log's write, capture and
 * integrity failure events and SSO's key-nearing-expiry event is registered
 * from `boot()`, whatever the configuration says; each hands the event to the
 * listeners `iam.audit.alerts` names for it, read at the dispatch, in order,
 * resolved from the application current then, so under Octane the request's
 * sandbox's; with none named the package sends nothing; a malformed value is
 * refused at the dispatch, never at boot, and by `validate()` for `iam:check`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OperationalAlerts::class)]
#[CoversClass(IamServiceProvider::class)]
final class OperationalAlertsTest extends TestCase
{
    use RunsInOctaneSandboxes;

    /** @var string The code the recording listener records. */
    private const string ALERTED = 'iam_test.alerted';

    /** @var \Tests\Fixtures\Audit\AlertInbox What the listeners were handed. */
    private AlertInbox $inbox;

    /**
     * Bind the inbox every listener writes to, and keep SSO's expiry event,
     * which is mapped too, out of any store.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        AuditLog::fake();

        $this->inbox = new AlertInbox;

        $this->app?->instance(AlertInbox::class, $this->inbox);
    }

    /**
     * The key and the alerts are the shipped configuration's, each naming no
     * listener.
     *
     * @return void
     */
    public function testTheAlertsAreTheShippedConfigurations(): void
    {
        $shipped = require dirname(__DIR__, 3) . '/config/iam.php';

        self::assertIsArray($shipped);
        self::assertIsArray($shipped['audit']);
        self::assertSame('iam.audit.alerts', OperationalAlerts::KEY);
        self::assertSame([
            'audit_write_failed'     => AuditWriteFailed::class,
            'audit_capture_failed'   => AuditCaptureFailed::class,
            'integrity_check_failed' => IntegrityCheckFailed::class,
            'key_nearing_expiry'     => KeyNearingExpiry::class,
        ], OperationalAlerts::EVENTS);
        self::assertSame(array_fill_keys(array_keys(OperationalAlerts::EVENTS), []), $shipped['audit']['alerts']);
    }

    /**
     * Rows of `[alert, event]`: every operational event.
     *
     * @return iterable<string, array{0: string, 1: object}>
     */
    public static function provideOperationalEvents(): iterable
    {
        foreach (self::events() as $alert => $event) {
            yield $alert => [$alert, $event];
        }
    }

    /**
     * Each event is handed to the listeners named for it, in the order named,
     * through `handle()` or by being invoked.
     *
     * @param  string  $alert
     * @param  object  $event
     * @return void
     */
    #[DataProvider('provideOperationalEvents')]
    public function testEachEventReachesItsListenersInOrder(string $alert, object $event): void
    {
        self::assertTrue(Event::hasListeners($event::class));

        $this->app?->make('config')->set(OperationalAlerts::KEY . '.' . $alert, [HandlesAlerts::class, InvokedOnAlerts::class, HandlesAlerts::class]);

        Event::dispatch($event);

        self::assertSame([[HandlesAlerts::class, $event], [InvokedOnAlerts::class, $event], [HandlesAlerts::class, $event]], $this->inbox->received());
    }

    /**
     * A listener named alone, not in a list, is handed the event, and no other
     * alert's listener hears it.
     *
     * @return void
     */
    public function testAListenerNamedAloneHearsOnlyItsEvent(): void
    {
        $events = self::events();

        $this->app?->make('config')->set(OperationalAlerts::KEY . '.key_nearing_expiry', HandlesAlerts::class);

        foreach ($events as $event) {
            Event::dispatch($event);
        }

        self::assertSame([[HandlesAlerts::class, $events['key_nearing_expiry']]], $this->inbox->received());
    }

    /**
     * Rows of `[alerts]` naming no listener for any event: the shipped empty
     * lists, `null`, and no key at all.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideNoListeners(): iterable
    {
        yield 'empty lists' => [array_fill_keys(array_keys(OperationalAlerts::EVENTS), [])];

        yield 'null' => [array_fill_keys(array_keys(OperationalAlerts::EVENTS), null)];

        yield 'no keys' => [[]];

        yield 'no alerts at all' => [null];
    }

    /**
     * With no listener named, the package sends nothing, and nothing fails.
     *
     * @param  mixed  $alerts
     * @return void
     */
    #[DataProvider('provideNoListeners')]
    public function testWithNoListenerNamedNothingIsSent(mixed $alerts): void
    {
        $this->app?->make('config')->set(OperationalAlerts::KEY, $alerts);

        foreach (self::events() as $event) {
            Event::dispatch($event);
        }

        self::assertSame([], $this->inbox->received());
    }

    /**
     * The listeners are read at each dispatch: one named after an earlier
     * dispatch hears the next, and one no longer named does not.
     *
     * @return void
     */
    public function testTheListenersAreReadAtEachDispatch(): void
    {
        $config = $this->app?->make('config');
        $event  = self::events()['audit_write_failed'];

        Event::dispatch($event);

        $config?->set(OperationalAlerts::KEY . '.audit_write_failed', [HandlesAlerts::class]);

        Event::dispatch($event);

        $config?->set(OperationalAlerts::KEY . '.audit_write_failed', []);

        Event::dispatch($event);

        self::assertSame([[HandlesAlerts::class, $event]], $this->inbox->received());
    }

    /**
     * Under Octane, the listener is resolved from the request's sandbox,
     * through the events dispatcher the worker resolved before the sandbox was
     * made, never from the worker's own application.
     *
     * @return void
     */
    public function testTheSandboxsListenerIsHanded(): void
    {
        $this->app?->make('events');
        $this->app?->make('config')->set(OperationalAlerts::KEY . '.audit_capture_failed', [HandlesAlerts::class]);

        $event   = self::events()['audit_capture_failed'];
        $sandbox = new AlertInbox;

        $this->inOctaneSandbox(static function (Application $app) use ($event, $sandbox): void {

            $app->instance(AlertInbox::class, $sandbox);

            Event::dispatch($event);
        });

        self::assertSame([], $this->inbox->received());
        self::assertSame([[HandlesAlerts::class, $event]], $sandbox->received());
    }

    /**
     * Rows of `[value]` that name no listener.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedListeners(): iterable
    {
        yield 'true' => [true];

        yield 'a number' => [1];

        yield 'blank text' => [' '];

        yield 'a map' => [['first' => HandlesAlerts::class]];

        yield 'a list holding a number' => [[HandlesAlerts::class, 1]];

        yield 'a list holding empty text' => [['']];
    }

    /**
     * A value that names no listener refuses the dispatch, naming the key and
     * never the value; boot is never refused.
     *
     * @param  mixed  $listeners
     * @return void
     */
    #[DataProvider('provideMalformedListeners')]
    public function testAMalformedValueRefusesTheDispatch(mixed $listeners): void
    {
        $this->app?->make('config')->set(OperationalAlerts::KEY . '.integrity_check_failed', $listeners);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`iam.audit.alerts.integrity_check_failed` must be a listener\'s class name or a list of them.');

        Event::dispatch(self::events()['integrity_check_failed']);
    }

    /**
     * Rows of `[alerts]` that map no alert to its listeners.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideAlertsThatAreNoMap(): iterable
    {
        yield 'text' => ['pager'];

        yield 'true' => [true];

        yield 'a number' => [1];
    }

    /**
     * An alerts configuration that is no map refuses every dispatch, never read
     * as naming no listener, so a broken alerting configuration is never
     * silent.
     *
     * @param  mixed  $alerts
     * @return void
     */
    #[DataProvider('provideAlertsThatAreNoMap')]
    public function testAlertsThatAreNoMapRefuseTheDispatch(mixed $alerts): void
    {
        $this->app?->make('config')->set(OperationalAlerts::KEY, $alerts);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`iam.audit.alerts` must map each alert to its listeners.');

        Event::dispatch(self::events()['audit_write_failed']);
    }

    /**
     * A listener with neither a `handle()` method nor `__invoke()` is refused,
     * naming the key.
     *
     * @return void
     */
    public function testAListenerThatCannotBeHandedTheEventIsRefused(): void
    {
        $this->app?->make('config')->set(OperationalAlerts::KEY . '.audit_write_failed', [HearsNoAlerts::class]);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The listener named in `iam.audit.alerts.audit_write_failed` has neither a handle() method nor __invoke().');

        Event::dispatch(self::events()['audit_write_failed']);
    }

    /**
     * A listener's failure propagates to the dispatch, so a broken alert is
     * never silent, and stops the listeners named after it.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAListenersFailurePropagatesToTheDispatch(): void
    {
        $broken = new \RuntimeException('The pager is down.');

        $this->app?->bind('alerts.broken', static fn (): \Closure => static fn (object $event): never => throw $broken);
        $this->app?->make('config')->set(OperationalAlerts::KEY . '.key_nearing_expiry', ['alerts.broken', HandlesAlerts::class]);

        try {
            Event::dispatch(self::events()['key_nearing_expiry']);

            self::fail('The listener\'s failure did not propagate.');
        } catch (\RuntimeException $thrown) {
            self::assertSame($broken, $thrown);
        }

        self::assertSame([], $this->inbox->received());
    }

    /**
     * Provide each failure audit-log dispatches inside its write guard, made to
     * happen.
     *
     * @return iterable<string, array{string, \Closure(): void}>
     */
    public static function provideGuardedFailures(): iterable
    {
        yield 'a write failed' => ['audit_write_failed', static function (): void {

            FakeAuditStore::failing(new \RuntimeException('The store is down.'));

            try {
                AuditLog::record(self::ALERTED);
            } catch (\Throwable) {
                // Whether the failed write propagates is audit-log's to decide
            }
        }];

        yield 'a capture failed' => ['audit_capture_failed', static function (): void {

            $identity = new PlainIdentity(['id' => str_repeat('9', 192)]);

            Event::dispatch(new SessionCreated(new AuthenticationContext('api', new ClientContext(null, null), $identity, sessionId: 'session-1')));
        }];
    }

    /**
     * Audit-log dispatches `AuditWriteFailed` and `AuditCaptureFailed` inside
     * its write guard, so a record their listener makes is refused, never
     * written.
     *
     * @param  string  $alert
     * @param  \Closure(): void  $fail
     * @return void
     */
    #[DataProvider('provideGuardedFailures')]
    public function testAGuardedFailuresListenerCannotRecord(string $alert, \Closure $fail): void
    {
        $stores = $this->recordOn($alert);

        $fail();

        self::assertSame([], self::alertRecords($stores));
    }

    /**
     * Provide each operational event raised outside audit-log's write guard,
     * raised as its member raises it.
     *
     * @return iterable<string, array{string, \Closure(\Illuminate\Foundation\Application): void}>
     */
    public static function provideUnguardedEvents(): iterable
    {
        yield 'an integrity check failed' => ['integrity_check_failed', static function (Application $app): void {

            $event = self::events()['integrity_check_failed'];

            assert($event instanceof IntegrityCheckFailed);

            $app->make(IntegrityAlarm::class)->raise($event);
        }];

        yield 'a key nearing expiry' => ['key_nearing_expiry', static function (): void {

            Event::dispatch(self::events()['key_nearing_expiry']);
        }];
    }

    /**
     * Audit-log raises `IntegrityCheckFailed` outside its write guard, and SSO
     * dispatches `KeyNearingExpiry` with none, so a record their listener makes
     * is written: a listener of either must alert by other means.
     *
     * @param  string  $alert
     * @param  \Closure(\Illuminate\Foundation\Application): void  $raise
     * @return void
     */
    #[DataProvider('provideUnguardedEvents')]
    public function testAnUnguardedEventsListenerCouldRecord(string $alert, \Closure $raise): void
    {
        $stores = $this->recordOn($alert);

        $raise($this->app ?? self::fail('The application has not booted.'));

        self::assertCount(1, self::alertRecords($stores));
    }

    /**
     * The shipped configuration, and one naming bound or existing listeners,
     * pass `validate()`.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function testAWellFormedConfigurationIsValid(): void
    {
        $alerts = $this->alerts();

        $alerts->validate();

        $this->app?->bind('alerts.pager', HandlesAlerts::class);
        $this->app?->make('config')->set(OperationalAlerts::KEY, [
            'audit_write_failed'   => [HandlesAlerts::class, 'alerts.pager'],
            'key_nearing_expiry'   => InvokedOnAlerts::class,
            'audit_capture_failed' => null,
        ]);

        $alerts->validate();

        $this->app?->make('config')->set(OperationalAlerts::KEY, null);

        $alerts->validate();

        $this->addToAssertionCount(1);
    }

    /**
     * Rows of `[alerts, message]` that `validate()` refuses.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideInvalidAlerts(): iterable
    {
        yield 'no map' => ['pager', '`iam.audit.alerts` must map each alert to its listeners.'];

        yield 'an alert that does not exist' => [
            ['audit_read_failed' => [HandlesAlerts::class]],
            '`iam.audit.alerts` names no alert `audit_read_failed`; the alerts are audit_write_failed, audit_capture_failed, integrity_check_failed, key_nearing_expiry.',
        ];

        yield 'a listener that is neither bound nor a class' => [
            ['audit_write_failed' => ['App\Listeners\Missing']],
            'A listener named in `iam.audit.alerts.audit_write_failed` is neither bound nor a class.',
        ];

        yield 'a class with neither handle() nor __invoke()' => [
            ['integrity_check_failed' => [HandlesAlerts::class, HearsNoAlerts::class]],
            'The listener named in `iam.audit.alerts.integrity_check_failed` has neither a handle() method nor __invoke().',
        ];

        yield 'a value that names no listener' => [
            ['key_nearing_expiry' => [1]],
            '`iam.audit.alerts.key_nearing_expiry` must be a listener\'s class name or a list of them.',
        ];
    }

    /**
     * `validate()` refuses an alert that does not exist, a value that names no
     * listener, a listener neither bound nor a class, and a class that could
     * not be handed the event, with neither `handle()` nor `__invoke()`, for
     * `iam:check`.
     *
     * @param  mixed  $alerts
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideInvalidAlerts')]
    public function testValidateRefusesAMalformedConfiguration(mixed $alerts, string $message): void
    {
        $this->app?->make('config')->set(OperationalAlerts::KEY, $alerts);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $this->alerts()->validate();
    }

    /**
     * The alerts as the container builds them.
     *
     * @return \SineMacula\Laravel\Iam\Audit\OperationalAlerts
     */
    private function alerts(): OperationalAlerts
    {
        return $this->app?->make(OperationalAlerts::class) ?? self::fail('The application has not booted.');
    }

    /**
     * Name a listener for the alert that binds a working fake store and records
     * `ALERTED` in it each time it is handed the event, and return the stores
     * it bound, one for each event it was handed.
     *
     * @param  string  $alert
     * @return \ArrayObject<int, \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore>
     */
    private function recordOn(string $alert): \ArrayObject
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore> $stores */
        $stores = new \ArrayObject;

        $this->app?->bind('alerts.recording', static fn (): \Closure => static function () use ($stores): void {

            // A working store, so a record let through would be kept, even
            // after a write that failed
            $stores->append(FakeAuditStore::fake());

            AuditLog::record(self::ALERTED);
        });

        $this->app?->make('config')->set(OperationalAlerts::KEY . '.' . $alert, ['alerts.recording']);

        return $stores;
    }

    /**
     * The records of `ALERTED` the one store the listener bound holds.
     *
     * @param  \ArrayObject<int, \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore>  $stores
     * @return list<\SineMacula\Laravel\AuditLog\Records\AuditRecord>
     */
    private static function alertRecords(\ArrayObject $stores): array
    {
        self::assertCount(1, $stores);

        $store = $stores[0] ?? self::fail('The listener bound no store.');

        return $store->recorded(static fn (AuditRecord $record): bool => $record->event === self::ALERTED);
    }

    /**
     * One of each operational event, by its alert.
     *
     * @return array<string, object>
     */
    private static function events(): array
    {
        $statuses = ['intact' => 0, 'altered' => 1];
        $context  = new EventContext(CarbonImmutable::now());

        return [
            'audit_write_failed'     => new AuditWriteFailed('0190c4a0-0000-7000-8000-000000000001', 'authentication.signed_in', 'DatabaseStore', \PDOException::class),
            'audit_capture_failed'   => new AuditCaptureFailed('App\Events\Shipped', 'App\Audit\ShippedMapper', \LogicException::class),
            'integrity_check_failed' => new IntegrityCheckFailed('verify', $statuses, ['anchored' => 0], 'hash_mismatch', null, 4, null, true),
            'key_nearing_expiry'     => new KeyNearingExpiry($context, 'key-1', KeyUse::SP_SIGNING, str_repeat('a', 64), CarbonImmutable::now()->addDays(7), 7),
        ];
    }
}
