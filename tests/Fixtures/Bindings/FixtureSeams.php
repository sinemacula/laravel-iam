<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use Tests\Fixtures\Bindings\Contracts\ClosureSeam;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;

/**
 * A capability's seam bindings over the fixture members' seams, one for each
 * lifetime: the adapter is transient over the plain-bound seam, shared over the
 * `singletonIf()` one, and scoped over the closure one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FixtureSeams implements ProvidesSeams
{
    /**
     * Return the fixture seam bindings.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        return [
            new SeamBinding(PlainSeam::class, Adapter::class, [MemberDefault::class]),
            new SeamBinding(SharedSeam::class, Adapter::class, [MemberDefault::class], Lifetime::SHARED),
            new SeamBinding(ClosureSeam::class, Adapter::class, [ConditionalBindingMemberProvider::class], Lifetime::SCOPED),
        ];
    }
}
