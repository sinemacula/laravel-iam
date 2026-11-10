<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\MemberDefaults;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Checks\Contracts\AuthenticationCheck;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Sso\SsoSeams;

/**
 * Every mandatory seam is bound to something other than its member's permissive
 * or inert default (IAM-10.2).
 *
 * Which seams are mandatory, and when, is the binding rule's own data: each
 * capability's rows (`SeamBinding::isMandatory()`), declared again from the
 * configuration and the container as they stand when the check runs, so a
 * mandate that follows a setting (SSO's enforcement, a tenant MFA requirement,
 * a tenant tree, SSO in use, the machine credentials the bound application
 * policy accepts) is read as it is now. A mandatory seam is checked whatever
 * this package's capability switch says: with the switch off, the application
 * binds the seam itself, under the same mandate.
 *
 * A mandatory seam fails when it is unbound, or when its live binding
 * (`SeamHolders`) names one of the row's member defaults, or any class of a
 * member's own other than the row's adapter and the member classes the row
 * accepts (`SeamBinding::$accepted`, SSO's `LinkStore` on the link storage, as
 * SSO's guide binds it): the defaults the members bind are their permissive or
 * inert ones, and a member that renames its default (which the binding rule
 * then keeps as though it were the application's) is caught here rather than
 * passed. A seam the application bound to a member's own default class by name
 * is reported too, though the rule keeps it. A member that says itself whether
 * the seam holds its default (`laravel-authorization`'s `isPackageDefault()`,
 * `SeamBinding::$holdsDefault`) is asked instead of its own classes being
 * refused wholesale: while it says the seam holds its default, the seam is
 * named by the row's default class and refused, and otherwise only the row's
 * defaults are, so a class the application names in that member's
 * configuration, which the member binds through a closure of its own, is
 * passed. A binding that names no class (a closure of the application's own,
 * whose implementation cannot be read without building it) is refused too: the
 * check takes nothing on trust, so a mandatory seam is bound by class name or
 * as an instance.
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
 * The seams that are `laravel-authentication`'s own contracts, and their notes,
 * are about no one guard, and `authentication:check` reports them too.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MandatorySeamsCheck implements AuthenticationCheck
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

    /** @var string The namespace of `laravel-authentication`'s own seams. */
    private const string AUTHENTICATION_NAMESPACE = 'SineMacula\Laravel\Authentication\\';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Checks\SeamHolders  $holders
     * @param  \SineMacula\Laravel\Iam\Bindings\MemberDefaults  $defaults
     */
    public function __construct(

        /** The container the seams are bound in, and the capabilities resolved from. */
        private Container $container,

        /** The configuration the mandates are read from. */
        private Repository $config,

        /** Names the class each seam's live binding answers with. */
        private SeamHolders $holders,

        /** Tells whether a seam holds its member's own binding. */
        private MemberDefaults $defaults = new MemberDefaults,
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
        return [...$this->checksFor(...$this->capabilities()), ...$this->keptNotes($this->kept())];
    }

    /**
     * The checks of the mandatory seams that are `laravel-authentication`'s
     * own, then the notes of its seams the binding rule kept with the
     * application's binding.
     *
     * @return list<\Closure(): mixed>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function authenticationChecks(): array
    {
        $bindings = array_filter($this->mandatory(...$this->capabilities()), static fn (SeamBinding $binding): bool => self::isAuthentications($binding->abstract));
        $kept     = array_filter($this->kept(), self::isAuthentications(...));

        return [...$this->assertions($bindings), ...$this->keptNotes($kept)];
    }

    /**
     * None: no seam is about one guard.
     *
     * @param  string  $guard
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function guardChecks(string $guard): array
    {
        return [];
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
        return $this->assertions($this->mandatory(...$capabilities));
    }

    /**
     * The capabilities whose mandatory seams this check reports: every one but
     * those the check of SSO's side holds.
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
     * One check for each seam, refusing it left unbound or on a member's
     * default.
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

        $holder = $this->holderOf($binding);

        if ($holder === null) {
            throw new \LogicException(sprintf(self::OPAQUE, $binding->abstract, $binding->adapter));
        }

        if (!self::isMemberDefault($binding, $holder)) {
            return;
        }

        throw new \LogicException(sprintf(self::ON_DEFAULT, $binding->abstract, $holder, $binding->adapter));
    }

    /**
     * The class the seam's live binding answers with. A seam whose member says
     * it holds the member's default (`SeamBinding::$holdsDefault`) answers with
     * the row's default class, which the member's binding resolves to.
     *
     * @param  \SineMacula\Laravel\Iam\Bindings\SeamBinding  $binding
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function holderOf(SeamBinding $binding): ?string
    {
        if ($binding->holdsDefault !== null && $this->defaults->holdsDefault($this->container, $binding->abstract, $binding->holdsDefault)) {
            return $binding->memberDefaults[0] ?? $binding->abstract;
        }

        return $this->holders->of($this->container, $binding->abstract);
    }

    /**
     * The binding rule's outcome, as the provider kept it; `null` when none is
     * bound.
     *
     * @return ?\SineMacula\Laravel\Iam\Bindings\BindingOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function outcome(): ?BindingOutcome
    {
        $outcome = $this->container->bound(BindingOutcome::class) ? $this->container->make(BindingOutcome::class) : null;

        return $outcome instanceof BindingOutcome ? $outcome : null;
    }

    /**
     * The seams the binding rule kept with the application's binding; none when
     * no outcome is bound.
     *
     * @return list<class-string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function kept(): array
    {
        return $this->outcome()->kept ?? [];
    }

    /**
     * A note for every seam given, each kept with the application's binding.
     *
     * @param  array<array-key, string>  $kept
     * @return list<\Closure(): mixed>
     */
    private function keptNotes(array $kept): array
    {
        return array_values(array_map(static fn (string $abstract): \Closure => static fn (): string => sprintf(self::KEPT, $abstract), $kept));
    }

    /**
     * Whether the seam is one of `laravel-authentication`'s own contracts.
     *
     * @param  string  $abstract
     * @return bool
     */
    private static function isAuthentications(string $abstract): bool
    {
        return str_starts_with($abstract, self::AUTHENTICATION_NAMESPACE);
    }

    /**
     * Whether the class named is one of the row's member defaults, or any class
     * of a member's own other than the row's adapter (SSO's own link store is
     * the linker's) and the member classes the row accepts (SSO's link store on
     * the link storage). A member that says itself whether the seam holds its
     * default has said so already (`holderOf()`), so only the row's defaults
     * are refused for it: its own class that declares the closure binding a
     * class the application names in its configuration is passed.
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

        return in_array($holder, $binding->memberDefaults, true) || ($binding->holdsDefault === null && SeamHolders::isMembersOwn($holder));
    }
}
