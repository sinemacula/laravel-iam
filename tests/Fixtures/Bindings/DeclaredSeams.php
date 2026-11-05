<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;

/**
 * A capability declaring the seam bindings it is given, whatever the
 * configuration, and keeping a copy of the configuration they are read from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DeclaredSeams implements ProvidesSeams
{
    /** @var ?\Illuminate\Contracts\Config\Repository A copy of the configuration the bindings were last read from, as it stood then. */
    public ?Repository $switches = null;

    /** @var list<\SineMacula\Laravel\Iam\Bindings\SeamBinding> The bindings declared. */
    private readonly array $bindings;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Bindings\SeamBinding  ...$bindings
     */
    public function __construct(SeamBinding ...$bindings)
    {
        $this->bindings = array_values($bindings);
    }

    /**
     * Return the bindings, and keep a copy of the configuration they are read
     * from.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $this->switches = new ConfigRepository($config->all());

        return $this->bindings;
    }
}
