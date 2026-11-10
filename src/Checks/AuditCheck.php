<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Iam\Audit\AuditRegistrations;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use SineMacula\Laravel\Iam\Audit\OperationalAlerts;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;

/**
 * The audit trail's configuration across the members (IAM-9, IAM-2.5).
 *
 * Audit-log is configured the way IAM-2.5 states, whatever the mappers say,
 * which `iam:install` writes and this enforces (decision Q5 (a)): every `jwt`
 * and `api_key` guard is in `audit-log.capture.laravel.except_guards`
 * (`CaptureExclusions`), audit-log's Gate capture is off, since
 * `laravel-authorization` is always installed, and
 * `audit-log.definitions.require_registered` is on (`AuditSettings`). Without
 * them each sign-in is recorded twice, by audit-log's own capture and by
 * whatever maps the members' events (this package's mappers, or the
 * application's own with them off), each decision recorded through the Gate, or
 * a code without a definition recorded unchecked. Audit-log's provider is
 * registered, whatever the mappers say, since without it nothing the members do
 * is recorded: boot refuses that, but stands the refusal aside for `iam:check`,
 * so it is the one way `iam:check` meets this package's part unregistered (a
 * provider of this package's registered once the application has booted fails
 * its boot instead), and it is reported as what it is. While the mappers are on
 * (`iam.audit.mappers`) and audit-log's provider is registered, this package's
 * part is registered with audit-log too; that alone follows the switch.
 *
 * The operational alerts (`iam.audit.alerts`) are validated whatever the
 * mappers say (`OperationalAlerts::validate()`): an alert that does not exist,
 * a listener that is neither bound nor a class, or a class, not bound, with
 * neither a `handle()` method nor `__invoke()`, would otherwise be found only
 * at the dispatch, when the alert it carries is lost. A name bound in the
 * container is not built here, so its shape is found only at the dispatch.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuditCheck implements Check
{
    /** @var string Why an application without audit-log's provider is refused. */
    private const string NO_AUDIT_LOG = 'laravel-audit-log\'s provider (%s) is not registered, so no member event is recorded: '
        . 'register it, or stop package discovery leaving it out.';

    /** @var string Why mappers never registered with a registered audit-log are refused. */
    private const string UNREGISTERED = 'The audit mappers are not registered with laravel-audit-log; '
        . 'register laravel-iam\'s provider before the application boots, or turn `%s` off.';

    /** @var string Why a guard audit-log's own capture still records is refused. */
    private const string UNEXCLUDED = 'Guards [%s] are missing from `%s`, so each of their sign-ins is recorded twice; `iam:install` writes them.';

    /** @var string Why audit-log's Gate capture on is refused. */
    private const string GATE_CAPTURE_ON = '`%s` must be false, so no authorization decision is recorded twice:'
        . ' this package maps laravel-authorization\'s decision events, the Gate checks laravel-authorization answers among them.';

    /** @var string Why audit-log recording unregistered codes is refused. */
    private const string UNCHECKED_CODES = '`%s` must be true, so a code without a definition is refused rather than recorded unchecked; '
        . '`iam:install` writes it.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Iam\Audit\AuditSettings  $settings
     * @param  \SineMacula\Laravel\Iam\Audit\CaptureExclusions  $exclusions
     * @param  \SineMacula\Laravel\Iam\Audit\OperationalAlerts  $alerts
     */
    public function __construct(

        /** The application whose providers are read and this package's registration is recorded in. */
        private Application $app,

        /** Reads the mappers' switch and audit-log's refusal of unregistered codes. */
        private AuditSettings $settings,

        /** Reads audit-log's capture exclusions and Gate capture. */
        private CaptureExclusions $exclusions,

        /** Validates the operational alerts' listeners. */
        private OperationalAlerts $alerts,
    ) {}

    /**
     * The subject the findings are reported under.
     *
     * @return string
     */
    #[\Override]
    public function subject(): string
    {
        return 'audit';
    }

    /**
     * The check always applies: only the mappers' registration follows their
     * switch.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * The alerts, audit-log's provider, the mappers' registration while they
     * are on, then the guards' exclusion, Gate capture and the refusal of
     * unregistered codes.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $registration = $this->settings->mapsEvents() ? [fn () => $this->assertRegistered()] : [];

        return [
            fn () => $this->alerts->validate(),
            fn () => $this->assertAuditLogRegistered(),
            ...$registration,
            fn () => $this->assertExcluded(),
            fn () => $this->assertGateCaptureOff(),
            fn () => $this->assertRequiresRegistered(),
        ];
    }

    /**
     * Refuse an application whose audit-log provider never registered.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertAuditLogRegistered(): void
    {
        if ($this->isAuditLogRegistered()) {
            return;
        }

        throw new \LogicException(sprintf(self::NO_AUDIT_LOG, AuditLogServiceProvider::class));
    }

    /**
     * Refuse mappers that were never registered with an audit-log whose
     * provider is registered; one whose provider is not is refused by
     * `assertAuditLogRegistered()` alone.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertRegistered(): void
    {
        if ($this->app->bound(AuditRegistrations::REGISTERED) || !$this->isAuditLogRegistered()) {
            return;
        }

        throw new \LogicException(sprintf(self::UNREGISTERED, AuditSettings::MAPPERS));
    }

    /**
     * Whether audit-log's provider has registered with the application.
     *
     * @return bool
     */
    private function isAuditLogRegistered(): bool
    {
        return $this->app->getProviders(AuditLogServiceProvider::class) !== [];
    }

    /**
     * Refuse a `jwt` or `api_key` guard audit-log's own capture still records.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertExcluded(): void
    {
        $unexcluded = $this->exclusions->unexcludedGuards();

        if ($unexcluded === []) {
            return;
        }

        throw new \LogicException(sprintf(self::UNEXCLUDED, implode(', ', $unexcluded), CaptureExclusions::EXCEPT_GUARDS_KEY));
    }

    /**
     * Refuse audit-log's Gate capture on.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertGateCaptureOff(): void
    {
        if ($this->exclusions->isGateCaptureOff()) {
            return;
        }

        throw new \LogicException(sprintf(self::GATE_CAPTURE_ON, CaptureExclusions::GATE_KEY));
    }

    /**
     * Refuse audit-log recording a code without a definition.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertRequiresRegistered(): void
    {
        if ($this->settings->refusesUnregisteredCodes()) {
            return;
        }

        throw new \LogicException(sprintf(self::UNCHECKED_CODES, AuditSettings::REQUIRE_REGISTERED));
    }
}
