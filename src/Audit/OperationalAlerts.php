<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;

/**
 * Offers the suite's operational events to the application's alerting
 * (IAM-9.8): audit-log's `AuditWriteFailed`, `AuditCaptureFailed` and
 * `IntegrityCheckFailed`, and SSO's `KeyNearingExpiry`, each handed to the
 * listeners `iam.audit.alerts` names for it. The package sends nothing itself:
 * with no listener named, an event reaches no one of this package's.
 *
 * Each alert is named by a key of `iam.audit.alerts`
 * (`audit_write_failed`, `audit_capture_failed`, `integrity_check_failed`,
 * `key_nearing_expiry`), whose value is a listener's class name, a list of
 * them, or `null` or an empty list for none. A listener is resolved from the
 * application current at each dispatch, so under Octane it is the request's
 * sandbox's, and is handed the event through its `handle()` method, or by being
 * invoked when it has none; the listeners run synchronously, in the order
 * named, and a listener that needs a queue dispatches its own job. What one
 * throws propagates to the dispatch: audit-log reports a failure of its own
 * events' listeners and goes on, and SSO's expiry report, a console command,
 * fails, so a broken alert is never silent.
 *
 * One listener of each event is registered from this package's `boot()`,
 * whatever the configuration says, and the configuration is read at each
 * dispatch, as audit-log reads its own: a malformed value refuses no boot (the
 * commands that clear a cached configuration among them), and is refused when
 * its event is dispatched, naming the key and never the value, as is an
 * `iam.audit.alerts` that is no map at all; `validate()`
 * refuses it beforehand, for `iam:check`, with a listener class that could
 * never be handed the event. A key that names no alert is reported by
 * `validate()` and otherwise unread.
 *
 * Audit-log dispatches `AuditWriteFailed` and `AuditCaptureFailed` inside its
 * write guard, so a record their listener makes is refused, never written. It
 * raises `IntegrityCheckFailed` (from `audit-log:seal` and `audit-log:verify`)
 * outside it, and SSO's `KeyNearingExpiry` knows no write guard, so a listener
 * of either could record one, for an integrity failure into the very log just
 * found altered or unverifiable. Alerting is the listener's to do by other
 * means, whichever event it hears.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OperationalAlerts
{
    /** @var string The configuration key naming each alert's listeners. */
    public const string KEY = 'iam.audit.alerts';

    /** @var array<string, class-string> Each alert's key, and the event it is raised by. */
    public const array EVENTS = [
        'audit_write_failed'     => AuditWriteFailed::class,
        'audit_capture_failed'   => AuditCaptureFailed::class,
        'integrity_check_failed' => IntegrityCheckFailed::class,
        'key_nearing_expiry'     => KeyNearingExpiry::class,
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container each listener is resolved from. */
        private ContainerContract $container,

        /** The configuration naming each alert's listeners, read at each dispatch. */
        private Repository $config,
    ) {}

    /**
     * Register one listener of each operational event, from this package's
     * `boot()`, resolved from the application current at the dispatch, never
     * from the events dispatcher's container, which under Octane is the
     * worker's own application.
     *
     * @return void
     */
    public static function listen(): void
    {
        foreach (self::EVENTS as $alert => $event) {

            Event::listen($event, static function (object $raised) use ($alert): void {

                Container::getInstance()->make(self::class)->alert($alert, $raised);
            });
        }
    }

    /**
     * Refuse a configuration naming an alert that does not exist, a value that
     * is no listener's class name nor a list of them, a listener that is
     * neither bound nor a class, or a class, not bound, that has neither a
     * `handle()` method nor `__invoke()`, so could never be handed the event,
     * for `iam:check`. Nothing is built: a name bound in the container is built
     * only at the dispatch, which refuses what it builds when it cannot be
     * handed the event.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        foreach (array_keys($this->alerts()) as $alert) {

            if (!array_key_exists($alert, self::EVENTS)) {
                throw new \InvalidArgumentException(sprintf('`%s` names no alert `%s`; the alerts are %s.', self::KEY, $alert, implode(', ', array_keys(self::EVENTS))));
            }

            foreach ($this->listeners($alert) as $listener) {
                $this->validateListener($alert, $listener);
            }
        }
    }

    /**
     * Refuse a listener that is neither bound nor a class, and a class, not
     * bound, that has neither a `handle()` method nor `__invoke()`.
     *
     * @param  string  $alert
     * @param  string  $listener
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function validateListener(string $alert, string $listener): void
    {
        if ($this->container->bound($listener)) {
            return;
        }

        if (!class_exists($listener)) {
            throw new \InvalidArgumentException(sprintf('A listener named in `%s.%s` is neither bound nor a class.', self::KEY, $alert));
        }

        if (!method_exists($listener, 'handle') && !method_exists($listener, '__invoke')) {
            throw new \InvalidArgumentException(self::unhandled($alert));
        }
    }

    /**
     * Why a listener named for the alert could not be handed the event.
     *
     * @param  string  $alert
     * @return string
     */
    private static function unhandled(string $alert): string
    {
        return sprintf('The listener named in `%s.%s` has neither a handle() method nor __invoke().', self::KEY, $alert);
    }

    /**
     * Hand the event to every listener named for the alert, in order.
     *
     * @param  string  $alert
     * @param  object  $event
     * @return void
     *
     * @throws \LogicException
     */
    private function alert(string $alert, object $event): void
    {
        foreach ($this->listeners($alert) as $name) {

            $listener = $this->container->make($name);

            if (is_object($listener) && method_exists($listener, 'handle')) {
                $listener->handle($event);

                continue;
            }

            if (!is_callable($listener)) {
                throw new \LogicException(self::unhandled($alert));
            }

            $listener($event);
        }
    }

    /**
     * The configured map of each alert to its listeners: none for `null`.
     *
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function alerts(): array
    {
        $alerts = $this->config->get(self::KEY) ?? [];

        if (!is_array($alerts)) {
            throw new \InvalidArgumentException(sprintf('`%s` must map each alert to its listeners.', self::KEY));
        }

        return $alerts;
    }

    /**
     * The listeners named for the alert: none for `null` or an empty list. A
     * configuration that maps no alert at all is refused, never read as none,
     * so a broken alerting configuration is never silent.
     *
     * @param  string  $alert
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function listeners(string $alert): array
    {
        $key       = self::KEY . '.' . $alert;
        $listeners = $this->alerts()[$alert] ?? null;

        if ($listeners === null) {
            return [];
        }

        $listeners = is_string($listeners) ? [$listeners] : $listeners;

        if (!is_array($listeners) || !array_is_list($listeners)) {
            throw self::malformed($key);
        }

        foreach ($listeners as $listener) {

            if (!is_string($listener) || trim($listener) === '') {
                throw self::malformed($key);
            }
        }

        return $listeners;
    }

    /**
     * The refusal of an alert's value that names no listener.
     *
     * @param  string  $key
     * @return \InvalidArgumentException
     */
    private static function malformed(string $key): \InvalidArgumentException
    {
        return new \InvalidArgumentException(sprintf('`%s` must be a listener\'s class name or a list of them.', $key));
    }
}
