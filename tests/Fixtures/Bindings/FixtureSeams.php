<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use Tests\Fixtures\Bindings\Contracts\ClosureSeam;
use Tests\Fixtures\Bindings\Contracts\FeatureSeam;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\ScopedSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;
use Tests\Fixtures\Bindings\Contracts\TransientSeam;

/**
 * A capability's seam bindings over the fixture members' seams, with every
 * lifetime: the adapter is transient over the `bindIf()` seams, the closure one
 * included, and the plain one, shared over the `singletonIf()` one, and scoped
 * over the `scopedIf()` one, which only binds while its switch is on. The
 * feature seam binds only while a real member's feature switch, filled by that
 * member's own configuration file and environment, is on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FixtureSeams implements ProvidesSeams
{
    /** @var list<class-string> Every fixture seam, in the order the bindings declare them. */
    public const array SEAMS = [
        TransientSeam::class,
        SharedSeam::class,
        ScopedSeam::class,
        ClosureSeam::class,
        PlainSeam::class,
        FeatureSeam::class,
    ];

    /** @var string The switch that turns the scoped seam's binding off when it is `false`. */
    public const string SCOPED_SWITCH = 'iam-fixtures.scoped';

    /** @var string The member's feature switch that turns the feature seam's binding on when it is `true`: laravel-sso's scheduled refresh, on in its packaged configuration file and turned off with `SSO_METADATA_REFRESH`. */
    public const string FEATURE_SWITCH = 'sso.features.metadata_refresh';

    /** @var ?\Illuminate\Contracts\Config\Repository A copy of the configuration the bindings were last read from, as it stood then. */
    public ?Repository $switches = null;

    /**
     * Return the fixture seam bindings, and keep a copy of the configuration
     * they are read from.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $this->switches = new ConfigRepository($config->all());

        return [
            new SeamBinding(TransientSeam::class, Adapter::class, [MemberDefault::class], holdsDefault: MemberDefault::isPackageDefault(...)),
            new SeamBinding(SharedSeam::class, Adapter::class, [MemberDefault::class], Lifetime::SHARED, holdsDefault: MemberDefault::isPackageDefault(...)),
            new SeamBinding(
                ScopedSeam::class,
                Adapter::class,
                [MemberDefault::class],
                Lifetime::SCOPED,
                self::isScopedSeamOn(...),
                holdsDefault: MemberDefault::isPackageDefault(...),
            ),
            new SeamBinding(ClosureSeam::class, Adapter::class, [MemberDefault::class], holdsDefault: MemberDefault::isPackageDefault(...)),
            new SeamBinding(PlainSeam::class, Adapter::class, [MemberDefault::class], holdsDefault: MemberDefault::isPackageDefault(...)),
            new SeamBinding(FeatureSeam::class, Adapter::class, [MemberDefault::class], appliesWhen: self::isFeatureOn(...), holdsDefault: MemberDefault::isPackageDefault(...)),
        ];
    }

    /**
     * Whether the member's feature switch turns the feature seam's binding on:
     * only `true`, so a switch read before the member's configuration is merged
     * reads as off.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    private static function isFeatureOn(Repository $config): bool
    {
        return $config->get(self::FEATURE_SWITCH) === true;
    }

    /**
     * Whether the scoped seam's switch leaves its binding on: anything but
     * `false`, a missing switch included.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    private static function isScopedSeamOn(Repository $config): bool
    {
        return $config->get(self::SCOPED_SWITCH) !== false;
    }
}
