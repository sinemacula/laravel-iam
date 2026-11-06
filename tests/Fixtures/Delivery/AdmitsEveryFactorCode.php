<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Delivery;

use SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;

/**
 * Factor code counters that admit every code and count nothing, so a test of
 * how `laravel-authentication` delivers a further factor's code can send one
 * without MFA's counters deciding whether it may.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AdmitsEveryFactorCode implements FactorCodeCounters
{
    /**
     * Admit the code.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     */
    #[\Override]
    public function admit(FactorCodeBinding $binding): FactorCodeAdmission
    {
        return FactorCodeAdmission::admitted();
    }

    /**
     * Admit the attempt, counting nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  string  $challengeId
     * @param  bool  $passed
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     */
    #[\Override]
    public function report(FactorCodeBinding $binding, string $challengeId, bool $passed): FactorCodeAdmission
    {
        return FactorCodeAdmission::admitted();
    }
}
