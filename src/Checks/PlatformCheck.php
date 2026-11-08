<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Composer\InstalledVersions;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;

/**
 * The PHP extensions and the Composer plugin the members need are present
 * (IAM-2.8).
 *
 * The extensions are those the members require, SSO's eight, which cover
 * `laravel-authentication`'s and MFA's: this package's own `composer.json`
 * declares them, but Composer checks them only where it installs, so a PHP that
 * runs the application without one (another SAPI, another image) is caught
 * here. They are checked whether SSO is in use or not, since
 * `laravel-authentication` needs three of them too.
 *
 * SSO's SAML library finds the XML elements it reads through a registry that
 * the `simplesamlphp/composer-xmlprovider-installer` plugin writes, and only
 * when the application's `composer.json` allows the plugin to run: without it
 * the library cannot read a SAML message. The plugin is present when it is
 * installed and every installed package that provides elements
 * (`simplesamlphp-xmlprovider`) has its registry in the plugin's directory,
 * which the plugin links there as it installs the package. It fails closed: a
 * provider Composer lists without an install path, without a readable registry,
 * or whose registry cannot be digested is refused too, never passed as having
 * nothing to link.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PlatformCheck implements Check
{
    /** @var list<string> The extensions the members require. */
    public const array EXTENSIONS = ['bcmath', 'curl', 'dom', 'hash', 'libxml', 'mbstring', 'openssl', 'zlib'];

    /** @var string The Composer plugin that registers the SAML library's XML elements. */
    public const string PLUGIN = 'simplesamlphp/composer-xmlprovider-installer';

    /** @var string The type of the packages that provide XML elements. */
    public const string PROVIDER_TYPE = 'simplesamlphp-xmlprovider';

    /** @var string Where a provider keeps its registry, under its install path. */
    private const string REGISTRY = '/classes/element.registry.php';

    /** @var string Why a provider whose registry the plugin never linked is refused. */
    private const string UNREGISTERED = 'The Composer plugin %s has not registered the XML elements of %s; '
        . 'allow it under `config.allow-plugins` in the application\'s composer.json and install again.';

    /** @var string Why a provider whose registry cannot be read is refused. */
    private const string UNREADABLE = 'The XML element registry of %s cannot be read, so the Composer plugin %s cannot have registered it; install it again.';

    /** @var string The pattern of the registries the plugin links into its own directory. */
    private const string LINKED = '/classes/element.registry.*.php';

    /** @var \Closure(string): bool Whether an extension is loaded. */
    private \Closure $loaded;

    /** @var \Closure(string): ?string The install path of a package, `null` when it is not installed. */
    private \Closure $installPath;

    /** @var \Closure(string): list<string> The packages of a type. */
    private \Closure $packagesOfType;

    /**
     * Constructor.
     *
     * @param  ?\Closure(string): bool  $loaded
     * @param  ?\Closure(string): ?string  $installPath
     * @param  ?\Closure(string): list<string>  $packagesOfType
     */
    public function __construct(?\Closure $loaded = null, ?\Closure $installPath = null, ?\Closure $packagesOfType = null)
    {
        $installed = static fn (string $package): ?string => InstalledVersions::isInstalled($package) ? InstalledVersions::getInstallPath($package) : null;

        $this->loaded         = $loaded         ?? extension_loaded(...);
        $this->installPath    = $installPath    ?? $installed;
        $this->packagesOfType = $packagesOfType ?? InstalledVersions::getInstalledPackagesByType(...);
    }

    /**
     * The subject the findings are reported under.
     *
     * @return string
     */
    #[\Override]
    public function subject(): string
    {
        return 'platform';
    }

    /**
     * The check always applies.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * One check per extension, then the plugin.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [
            ...array_map(fn (string $extension): \Closure => fn () => $this->assertLoaded($extension), self::EXTENSIONS),
            fn () => $this->assertPluginRan(),
        ];
    }

    /**
     * Refuse an extension that is not loaded.
     *
     * @param  string  $extension
     * @return void
     *
     * @throws \LogicException
     */
    private function assertLoaded(string $extension): void
    {
        if (($this->loaded)($extension)) {
            return;
        }

        throw new \LogicException(sprintf('The PHP extension ext-%s is not loaded.', $extension));
    }

    /**
     * Refuse a plugin that is not installed, or that has not linked the
     * registry of every package providing XML elements.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertPluginRan(): void
    {
        $plugin = ($this->installPath)(self::PLUGIN);

        if ($plugin === null) {
            throw new \LogicException(sprintf('The Composer plugin %s is not installed.', self::PLUGIN));
        }

        $linked = array_map(self::digest(...), glob($plugin . self::LINKED) ?: []);

        foreach (($this->packagesOfType)(self::PROVIDER_TYPE) as $package) {

            $path   = ($this->installPath)($package);
            $digest = $path !== null ? self::digest($path . self::REGISTRY) : null;

            if ($digest === null) {
                throw new \LogicException(sprintf(self::UNREADABLE, $package, self::PLUGIN));
            }

            if (!in_array($digest, $linked, true)) {
                throw new \LogicException(sprintf(self::UNREGISTERED, self::PLUGIN, $package));
            }
        }
    }

    /**
     * The digest of a registry's content, which a linked copy shares, or `null`
     * when it is not a readable file or cannot be digested.
     *
     * @param  string  $file
     * @return ?string
     */
    private static function digest(string $file): ?string
    {
        if (!is_file($file) || !is_readable($file)) {
            return null;
        }

        $digest = hash_file('sha256', $file);

        return is_string($digest) ? $digest : null;
    }
}
