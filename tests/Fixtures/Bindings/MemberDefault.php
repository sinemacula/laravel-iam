<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Container\Container;
use Tests\Fixtures\Bindings\Contracts\ClosureSeam;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\ScopedSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;
use Tests\Fixtures\Bindings\Contracts\TransientSeam;

/**
 * The member's own default implementation of every fixture seam, which the
 * fixture members bind through `build()` and tell by `isPackageDefault()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MemberDefault implements ClosureSeam, PlainSeam, ScopedSeam, SharedSeam, TransientSeam
{
    /**
     * Build the default, as a fixture member binds it.
     *
     * @return self
     */
    public static function build(): self
    {
        return new self;
    }

    /**
     * Whether the seam is still bound to `build()`, as a member's own
     * `isPackageDefault()` answers.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  string  $abstract
     * @return bool
     *
     * @throws \ReflectionException
     */
    public static function isPackageDefault(Container $container, string $abstract): bool
    {
        $concrete = $container->getBindings()[$abstract]['concrete'] ?? null;

        return $concrete instanceof \Closure && (new \ReflectionFunction($concrete))->getClosureScopeClass()?->getName() === self::class;
    }
}
