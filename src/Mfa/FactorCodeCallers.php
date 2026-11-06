<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Mfa\Context\CallerContext;

/**
 * The caller MFA handed the challenge gateway, kept beside each factor code
 * binding the gateway hands `laravel-authentication`, so its factor code
 * counters can hand MFA's challenge counters the same caller (IAM-3.9).
 *
 * `laravel-authentication`'s factor code counters are handed the factor code
 * binding alone, the very instance the gateway sent or checked the code under,
 * and MFA's counters judge a caller: a pending sign-in's first factor and its
 * bootstrap enrolment, and the client an attempt is counted against, are the
 * caller's, not anything the binding says. The gateway keeps the caller here,
 * under that instance, before it hands the binding on (`hold()`), and the
 * counters read it back (`of()`); nothing is read from a request. A binding the
 * gateway did not make (`laravel-authentication`'s factor codes called some
 * other way) has no caller here, and the counters judge it as the binding's
 * identity's own.
 *
 * Each caller is kept only while its binding is: the bindings are weak keys, so
 * nothing outlives the code's send or check. It is bound scoped, under this
 * package's own key for scoped adapters, so it holds the callers of one
 * request, or one job, alone, and the worker reset forgets it (IAM-8.1).
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
