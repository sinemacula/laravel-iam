<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Mfa\Context\CallerContext;

/**
 * MFA's caller per factor code binding, since `laravel-authentication`'s
 * `FactorCodeCounters` receive only the binding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorCodeCallers
{
    /** @var \WeakMap<\SineMacula\Laravel\Authentication\Codes\FactorCodeBinding, \SineMacula\Laravel\Mfa\Context\CallerContext> The caller kept for each binding the gateway made. */
    private \WeakMap $callers;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->callers = new \WeakMap;
    }

    /**
     * Keep the caller for the binding, and answer the binding.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     */
    public function hold(FactorCodeBinding $binding, CallerContext $caller): FactorCodeBinding
    {
        $this->callers[$binding] = $caller;

        return $binding;
    }

    /**
     * The caller kept for the binding, or `null` when the gateway made none.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Context\CallerContext
     */
    public function of(FactorCodeBinding $binding): ?CallerContext
    {
        return $this->callers[$binding] ?? null;
    }
}
