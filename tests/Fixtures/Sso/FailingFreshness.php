<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * SSO's freshness, failing the first checks it is asked for with the failure
 * given, as the database would fail a statement there, then answering through
 * the freshness it stands in for.
 *
 * SSO asks freshness for a `link` inside the redemption's transaction, once it
 * has consumed the code, so each failure meets an attempt that has already
 * written the consumption.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailingFreshness implements Freshness
{
    /** @var int How many checks were asked for. */
    public int $calls = 0;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Freshness  $freshness
     * @param  \Closure(): \Throwable  $failure
     * @param  int  $failures
     */
    public function __construct(

        /** The freshness each check is answered through once the failures are spent. */
        private readonly Freshness $freshness,

        /** Builds the failure each failing check throws. */
        private readonly \Closure $failure,

        /** How many checks fail before one is answered. */
        private int $failures,
    ) {}

    /**
     * Fail the check while failures are left, and answer it through the
     * freshness otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     *
     * @throws \Throwable
     */
    #[\Override]
    public function check(FreshnessOperation $operation, int $maxAgeSeconds, ?Caller $caller): FreshnessOutcome
    {
        $this->calls++;

        if ($this->failures > 0) {

            $this->failures--;

            throw ($this->failure)();
        }

        return $this->freshness->check($operation, $maxAgeSeconds, $caller);
    }
}
