<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Iam\Audit\AuditRegistrations;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;

/**
 * Checks audit-log excludes `jwt` and `api_key` guards, has Gate capture off
 * and `require_registered` on, and holds the mappers while they are on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuditCheck implements Check
{
    /** @var string The failure for mappers never registered with audit-log. */
    private const string UNREGISTERED = 'The audit mappers are not registered with laravel-audit-log; '
        . 'register laravel-iam\'s provider before the application boots, or turn `%s` off.';

    /** @var string The failure for guards audit-log's own capture still records. */
    private const string UNEXCLUDED = 'Guards [%s] are missing from `%s`, so each of their sign-ins is recorded twice: add them.';

    /** @var string The failure for audit-log's Gate capture on. */
    private const string GATE_CAPTURE_ON = '`%s` must be false, so no authorization decision is recorded twice:'
        . ' this package maps laravel-authorization\'s decision events, the Gate checks laravel-authorization answers among them.';

    /** @var string The failure for audit-log recording unregistered codes. */
    private const string UNCHECKED_CODES = '`%s` must be true, so a code without a definition is refused rather than recorded unchecked; '
        . 'turn it on.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Iam\Audit\AuditSettings  $settings
     * @param  \SineMacula\Laravel\Iam\Audit\CaptureExclusions  $exclusions
     */
    public function __construct(

        /** The application the audit registration is recorded in. */
        private Application $app,

        /** Reads the mappers' switch and the refusal of unregistered codes. */
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
     * The check always applies; only the registration follows the mappers'
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
     * The mappers' registration while on, then exclusions, Gate capture and
     * codes.
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
