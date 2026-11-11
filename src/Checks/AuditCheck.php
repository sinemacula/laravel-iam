<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Iam\Audit\AuditRegistrations;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;

/**
 * Audit-log is configured as IAM-2.5 states (every `jwt` and `api_key` guard
 * excluded from its capture, Gate capture off, `require_registered` on), and the
 * mappers are registered while they are on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuditCheck implements Check
{
    /** @var string Why mappers never registered with audit-log are refused. */
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
     */
    public function __construct(

        /** The application this package's registration with audit-log is recorded in. */
        private Application $app,

        /** Reads the mappers' switch and audit-log's refusal of unregistered codes. */
        private AuditSettings $settings,

        /** Reads audit-log's capture exclusions and Gate capture. */
        private CaptureExclusions $exclusions,
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
     * The mappers' registration while they are on, then the guards' exclusion,
     * Gate capture and the refusal of unregistered codes.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $registration = $this->settings->mapsEvents() ? [fn () => $this->assertRegistered()] : [];

        return [
            ...$registration,
            fn () => $this->assertExcluded(),
            fn () => $this->assertGateCaptureOff(),
            fn () => $this->assertRequiresRegistered(),
        ];
    }

    /**
     * Refuse mappers that were never registered with audit-log.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertRegistered(): void
    {
        if ($this->app->bound(AuditRegistrations::REGISTERED)) {
            return;
        }

        throw new \LogicException(sprintf(self::UNREGISTERED, AuditSettings::MAPPERS));
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
