<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Contracts\Config\Repository;

/**
 * Reads the mappers' switch and audit-log's rule refusing unregistered codes.
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

        /** The configuration both settings are read from. */
        private Repository $config,
    ) {}

    /**
     * Whether the mappers record the members' events; only an explicit off
     * value turns them off, since a trail skipped by a typo is lost for good.
     *
     * @return bool
     */
    public function mapsEvents(): bool
    {
        $value = $this->config->get(self::MAPPERS);

        return $value === null || $value === '' || (filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? true);
    }

    /**
     * Whether audit-log refuses a code no definition registers.
     *
     * @return bool
     */
    public function refusesUnregisteredCodes(): bool
    {
        return $this->config->get(self::REQUIRE_REGISTERED, false) === true;
    }
}
