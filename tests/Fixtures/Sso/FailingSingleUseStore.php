<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

/**
 * SSO's single-use store, failing the first records it is asked to make with
 * the failure given, as the database would fail a redemption's transaction
 * there, then recording through the store it stands in for.
 *
 * SSO records a code there inside the redemption's transaction, after its locks
 * and before it consumes the code, so each failure rolls back the attempt it
 * met and leaves the code unspent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailingSingleUseStore implements SingleUseStore
{
    /** @var int How many records were asked for. */
    public int $calls = 0;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SingleUseStore  $store
     * @param  \Closure(): \Throwable  $failure
     * @param  int  $failures
     */
    public function __construct(

        /** The store each record is made through once the failures are spent. */
        private readonly SingleUseStore $store,

        /** Builds the failure each failing record throws. */
        private readonly \Closure $failure,

        /** How many records fail before one is made. */
        private int $failures,
    ) {}

    /**
     * Fail the record while failures are left, and make it through the store
     * otherwise.
     *
     * @param  string  $namespace
     * @param  string  $key
     * @param  \Carbon\CarbonImmutable  $until
     * @return \SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome
     *
     * @throws \Throwable
     */
    #[\Override]
    public function record(string $namespace, #[\SensitiveParameter] string $key, CarbonImmutable $until): SingleUseOutcome
    {
        $this->calls++;

        if ($this->failures > 0) {

            $this->failures--;

            throw ($this->failure)();
        }

        return $this->store->record($namespace, $key, $until);
    }
}
