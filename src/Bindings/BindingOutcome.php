<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

/**
 * What one run of the binding rule did: the seams it bound an adapter over and
 * the seams it left with the binding it found, for the checks to report.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BindingOutcome
{
    /**
     * Constructor.
     *
     * @param  list<class-string>  $bound
     * @param  list<class-string>  $kept
     */
    public function __construct(

        /** The seams bound to this package's adapter. */
        public array $bound,

        /** The seams left with the application's binding. */
        public array $kept,
    ) {}
}
