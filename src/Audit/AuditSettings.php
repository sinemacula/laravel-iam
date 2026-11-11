<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Contracts\Config\Repository;

/**
 * Whether the members' events are recorded in `laravel-audit-log` through this
 * package's mappers (IAM-9.1), as `iam.audit.mappers` says, and whether
 * audit-log refuses a code no definition registers, as IAM-2.5 asks.
 *
 * The switch is read leniently, as the members read a switch an environment
 * variable fills: `false`, as a boolean or as text, `0`, `off` and `no` turn it
 * off; anything else, a missing, empty or unrecognised value included, leaves
 * it on, since an audit trail skipped by a typo is lost for good, while one
 * recorded needlessly costs a row. It is read when it is asked, as the package
 * boots: audit-log takes registrations only until the application has booted.
 *
 * Audit-log's `definitions.require_registered` is only read here, never
 * written: the application turns it on and `iam:check` refuses a configuration
 * without it (decision Q5 (a)). It counts as on only while it is `true`, the
 * one value audit-log reads as on; anything else, unset included, is not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuditSettings
{
    /** @var string The configuration key of the mappers' switch. */
    public const string MAPPERS = 'iam.audit.mappers';

    /** @var string The key of audit-log's rule refusing a code no definition registers. */
    public const string REQUIRE_REGISTERED = 'audit-log.definitions.require_registered';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the switch is read from. */
        private Repository $config,
    ) {}

    /**
     * Whether the mappers record the members' events.
     *
     * @return bool
     */
    public function mapsEvents(): bool
    {
        $value = $this->config->get(self::MAPPERS);

        return $value === null || $value === '' || (filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? true);
    }

    /**
     * Whether audit-log refuses a code no definition registers, rather than
     * recording it under the permissive default.
     *
     * @return bool
     */
    public function refusesUnregisteredCodes(): bool
    {
        return $this->config->get(self::REQUIRE_REGISTERED, false) === true;
    }
}
