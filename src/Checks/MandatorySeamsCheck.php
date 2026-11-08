<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Sso\SsoSeams;

/**
 * Every mandatory seam is bound to something other than its member's permissive
 * or inert default (IAM-10.2).
 *
 * Which seams are mandatory, and when, is the binding rule's own data: each
 * capability's rows (`SeamBinding::$mandatory`), declared again from the
 * configuration and the container as they stand when the check runs, so a
 * mandate that follows a setting (SSO's enforcement, a tenant MFA requirement,
 * a tenant tree, SSO in use) is read as it is now. A mandatory seam is checked
 * whatever this package's capability switch says: with the switch off, the
 * application binds the seam itself, under the same mandate.
 *
 * A mandatory seam fails when it is unbound, or when its live binding
 * (`SeamHolders`) names one of the row's member defaults, or any class of a
 * member's own other than the row's adapter and the member classes the row
 * accepts (`SeamBinding::$accepted`, SSO's `LinkStore` on the link storage, as
 * SSO's guide binds it): the defaults the members bind are their permissive or
 * inert ones, and a member that renames its default (which the binding rule
 * then keeps as though it were the application's) is caught here rather than
 * passed. A seam the application bound to a member's own default class by name
 * is reported too, though the rule keeps it. A binding that names no class (a
 * closure of the application's own, whose implementation cannot be read without
 * building it) is refused too: the check takes nothing on trust, so a mandatory
 * seam is bound by class name or as an instance.
 *
 * While SSO is in use, the seams of the capabilities this package's check of
 * SSO's side holds (`SsoBridgeCheck::CAPABILITIES`) are left to that check,
 * which `sso:check` runs while it is the check SSO's checker runs under `iam`
 * (`SsoCheckRegistration::isInForce()`), and `SsoBridgeFallbackCheck` runs in
 * `iam:check` otherwise, so each mandatory seam is reported once; while SSO is
 * not in use, the bridge does not apply, and they are checked here.
 *
 * The binding rule's outcome (`BindingOutcome`), the seams it bound and kept as
 * the application registered, is reported as a note for every seam it kept with
 * the application's binding, so the application sees which of its bindings won.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MandatorySeamsCheck implements Check
{
    /** @var string Why an unbound mandatory seam is refused. */
    private const string UNBOUND = '%s is unbound; bind %s, or an implementation of your own, to it.';

    /** @var string Why a mandatory seam on a member's default is refused. */
    private const string ON_DEFAULT = '%s is still bound to %s, its member\'s permissive or inert default; '
        . 'bind %s, or an implementation of your own, to it.';

    /** @var string Why a mandatory seam whose implementation cannot be read is refused. */
    private const string OPAQUE = '%s is bound through a closure, whose implementation cannot be read without building it; '
        . 'bind %s, or an implementation of your own, to it by class name or as an instance.';

    /** @var string The note of a seam the binding rule kept with the application's binding. */
    private const string KEPT = '%s keeps the application\'s binding, not this package\'s adapter.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Checks\SeamHolders  $holders
     */
    public function __construct(

        /** The container the seams are bound in, and the capabilities resolved from. */
        private Container $container,

        /** The configuration the mandates are read from. */
        private Repository $config,

        /** Names the class each seam's live binding answers with. */
        private SeamHolders $holders,
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
     * The check always applies: a seam that is not mandatory now is simply not
     * checked.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * One check for each mandatory seam of every capability the check of SSO's
     * side does not hold, then a note for each seam the binding rule kept with
     * the application's binding.
     *
     * @return list<\Closure(): mixed>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function checks(): array
    {
        $providers    = array_diff(IamServiceProvider::seamProviders(), $this->heldBySso());
        $capabilities = array_map(fn (string $provider): ProvidesSeams => $this->container->make($provider), $providers);

        return [...$this->checksFor(...$capabilities), ...$this->keptNotes()];
    }

    /**
     * One check for each mandatory seam the capabilities declare now, each
     * refusing a seam left unbound or on a member's default.
     *
     * @param  \SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams  ...$capabilities
     * @return list<\Closure(): mixed>
     */
    public function checksFor(ProvidesSeams ...$capabilities): array
    {
        $checks = [];

        foreach ($capabilities as $capability) {

            foreach ($capability->seams($this->config) as $binding) {

                if (!$binding->mandatory) {
                    continue;
                }

                $checks[] = function () use ($binding): void {
                    $this->assertBound($binding);
                };
            }
        }

        return $checks;
    }

    /**
     * The capabilities whose mandatory seams this package's check of SSO's side
     * reports, through `sso:check` or `SsoBridgeFallbackCheck`, which applies
     * while SSO is in use; none while it is not.
     *
     * @return list<class-string<\SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams>>
     */
    private function heldBySso(): array
    {
        return SsoSeams::isInUse($this->config) ? SsoBridgeCheck::CAPABILITIES : [];
    }

    /**
     * Refuse a mandatory seam that is unbound or bound to a member's default.
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

        $holder = $this->holders->of($this->container, $binding->abstract);

        if ($holder === null) {
            throw new \LogicException(sprintf(self::OPAQUE, $binding->abstract, $binding->adapter));
        }

        if (!self::isMemberDefault($binding, $holder)) {
            return;
        }

        throw new \LogicException(sprintf(self::ON_DEFAULT, $binding->abstract, $holder, $binding->adapter));
    }

    /**
     * A note for every seam the binding rule kept with the application's
     * binding.
     *
     * @return list<\Closure(): mixed>
     */
    private function keptNotes(): array
    {
        $outcome = $this->container->bound(BindingOutcome::class) ? $this->container->make(BindingOutcome::class) : null;

        if (!$outcome instanceof BindingOutcome) {
            return [];
        }

        return array_map(static fn (string $abstract): \Closure => static fn (): string => sprintf(self::KEPT, $abstract), $outcome->kept);
    }

    /**
     * Whether the class named is one of the row's member defaults, or any class
     * of a member's own other than the row's adapter (SSO's own link store is
     * the linker's) and the member classes the row accepts (SSO's link store on
     * the link storage).
     *
     * @param  \SineMacula\Laravel\Iam\Bindings\SeamBinding  $binding
     * @param  string  $holder
     * @return bool
     */
    private static function isMemberDefault(SeamBinding $binding, string $holder): bool
    {
        if ($holder === $binding->adapter || in_array($holder, $binding->accepted, true)) {
            return false;
        }

        return in_array($holder, $binding->memberDefaults, true) || SeamHolders::isMembersOwn($holder);
    }
}
