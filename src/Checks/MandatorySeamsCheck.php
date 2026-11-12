<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Sso\SsoSeams;

/**
 * Checks every mandatory seam is bound off its member's permissive or inert
 * default.
 *
 * Mandates are read from the configuration as it stands, whatever the switches
 * say. While SSO is in use, `SsoBridgeCheck` covers its seams.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MandatorySeamsCheck implements Check
{
    /** @var string The failure for an unbound mandatory seam. */
    private const string UNBOUND = '%s is unbound; bind %s, or an implementation of your own, to it.';

    /** @var string The failure for a mandatory seam on its member's default. */
    private const string ON_DEFAULT = '%s is still bound to its member\'s permissive or inert default; '
        . 'bind %s, or an implementation of your own, to it.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container the seams are bound in. */
        private Container $container,

        /** The configuration the mandates are read from. */
        private Repository $config,
    ) {}

    /**
     * The subject the findings are reported under.
     *
     * @return string
     */
    #[\Override]
    public function subject(): string
    {
        return 'seams';
    }

    /**
     * The check always applies; a seam not mandatory now is skipped.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * One check per mandatory seam the SSO bridge check does not cover.
     *
     * @return list<\Closure(): mixed>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function checks(): array
    {
        return $this->checksFor(...$this->capabilities());
    }

    /**
     * One check per mandatory seam of the capabilities.
     *
     * @param  \SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams  ...$capabilities
     * @return list<\Closure(): mixed>
     */
    public function checksFor(ProvidesSeams ...$capabilities): array
    {
        return $this->assertions($this->mandatory(...$capabilities));
    }

    /**
     * The capabilities this check covers.
     *
     * @return list<\SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function capabilities(): array
    {
        $providers = array_diff(IamServiceProvider::seamProviders(), $this->heldBySso());

        return array_values(array_map(fn (string $provider): ProvidesSeams => $this->container->make($provider), $providers));
    }

    /**
     * The mandatory seams the capabilities declare now.
     *
     * @param  \SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams  ...$capabilities
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    private function mandatory(ProvidesSeams ...$capabilities): array
    {
        $bindings = [];

        foreach ($capabilities as $capability) {
            $bindings = [...$bindings, ...array_filter($capability->seams($this->config), static fn (SeamBinding $binding): bool => $binding->isMandatory())];
        }

        return $bindings;
    }

    /**
     * One check per seam.
     *
     * @param  array<array-key, \SineMacula\Laravel\Iam\Bindings\SeamBinding>  $bindings
     * @return list<\Closure(): mixed>
     */
    private function assertions(array $bindings): array
    {
        return array_values(array_map(fn (SeamBinding $binding): \Closure => function () use ($binding): void {
            $this->assertBound($binding);
        }, $bindings));
    }

    /**
     * The capabilities the SSO bridge check covers while SSO is in use.
     *
     * @return list<class-string<\SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams>>
     */
    private function heldBySso(): array
    {
        return SsoSeams::isInUse($this->config) ? SsoBridgeCheck::CAPABILITIES : [];
    }

    /**
     * Refuse a seam that is unbound or holds its member's default.
     *
     * @param  \SineMacula\Laravel\Iam\Bindings\SeamBinding  $binding
     * @return void
     *
     * @throws \LogicException
     */
    private function assertBound(SeamBinding $binding): void
    {
        if (!$this->container->bound($binding->abstract)) {
            throw new \LogicException(sprintf(self::UNBOUND, $binding->abstract, $binding->adapter));
        }

        if ($binding->holdsDefault($this->container)) {
            throw new \LogicException(sprintf(self::ON_DEFAULT, $binding->abstract, $binding->adapter));
        }
    }
}
