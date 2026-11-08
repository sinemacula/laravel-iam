<?php

declare(strict_types = 1);

namespace Tests\Unit\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Checks\PlatformCheck;
use Tests\Concerns\RunsChecks;
use Tests\Concerns\UsesScratchDirectory;

/**
 * Unit tests for the platform check (IAM-2.8): every extension the members need
 * loaded, and SSO's Composer plugin installed with every XML provider's
 * registry linked into its directory.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PlatformCheck::class)]
final class PlatformCheckTest extends TestCase
{
    use RunsChecks, UsesScratchDirectory;

    /** @var string A registry's content, as an XML provider ships it. */
    private const string REGISTRY = "<?php\n\nreturn ['urn:example' => []];\n";

    /**
     * Delete the test's directory.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->deleteScratch();

        parent::tearDown();
    }

    /**
     * The platform the tests run on, read through PHP and Composer, passes, the
     * eight extensions SSO declares checked.
     *
     * @return void
     */
    public function testThisPlatformPasses(): void
    {
        $check = new PlatformCheck;

        self::assertSame([], self::problems($check->checks()));
        self::assertCount(9, $check->checks());
        self::assertSame(['bcmath', 'curl', 'dom', 'hash', 'libxml', 'mbstring', 'openssl', 'zlib'], PlatformCheck::EXTENSIONS);
        self::assertTrue($check->applies());
        self::assertSame('platform', $check->subject());
    }

    /**
     * Each extension that is not loaded is reported.
     *
     * @return void
     */
    public function testAMissingExtensionIsReported(): void
    {
        $loaded = static fn (string $extension): bool => !in_array($extension, ['bcmath', 'zlib'], true);
        $check  = new PlatformCheck($loaded, $this->installed(true), static fn (): array => ['acme/provider']);

        self::assertSame(['The PHP extension ext-bcmath is not loaded.', 'The PHP extension ext-zlib is not loaded.'], self::problems($check->checks()));
    }

    /**
     * A plugin that is not installed is reported.
     *
     * @return void
     */
    public function testAPluginNotInstalledIsReported(): void
    {
        $check = new PlatformCheck(static fn (): bool => true, static fn (): ?string => null, static fn (): array => []);

        self::assertSame(['The Composer plugin simplesamlphp/composer-xmlprovider-installer is not installed.'], self::problems($check->checks()));
    }

    /**
     * A provider whose registry the plugin never linked, as when the
     * application's composer.json does not allow the plugin, is reported.
     *
     * @return void
     */
    public function testAProviderWhoseRegistryIsNotLinkedIsReported(): void
    {
        $check = new PlatformCheck(static fn (): bool => true, $this->installed(false), static fn (): array => ['acme/provider']);

        $problem = 'The Composer plugin simplesamlphp/composer-xmlprovider-installer has not registered the XML elements of acme/provider; '
            . 'allow it under `config.allow-plugins` in the application\'s composer.json and install again.';

        self::assertSame([$problem], self::problems($check->checks()));

        $check = new PlatformCheck(static fn (): bool => true, $this->installed(true), static fn (): array => ['acme/provider']);

        self::assertSame([], self::problems($check->checks()));
    }

    /**
     * A provider that cannot be shown to be registered fails closed: one
     * Composer gives no install path, one without a registry, and one whose
     * registry cannot be read are each reported, never passed as having nothing
     * to link.
     *
     * @return void
     */
    public function testAProviderWhoseRegistryCannotBeReadIsReported(): void
    {
        $installed = $this->installed(true);

        foreach (['acme/bare', 'acme/absent'] as $package) {
            $check = new PlatformCheck(static fn (): bool => true, $installed, static fn (): array => ['acme/provider', $package]);

            self::assertSame([self::unreadable($package)], self::problems($check->checks()));
        }

        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            return;
        }

        $registry = $this->scratch('vendor/acme/provider/classes/element.registry.php');

        chmod($registry, 0o000);

        // An unreadable registry is refused before it is opened, so reading it
        // raises no warning
        set_error_handler(static function (int $level, string $message): never {
            throw new \ErrorException($message, 0, $level);
        });

        try {
            $check = new PlatformCheck(static fn (): bool => true, $installed, static fn (): array => ['acme/provider']);

            self::assertSame([self::unreadable('acme/provider')], self::problems($check->checks()));
        } finally {
            restore_error_handler();
            chmod($registry, 0o644);
        }
    }

    /**
     * The problem of a provider whose registry cannot be read.
     *
     * @param  string  $package
     * @return string
     */
    private static function unreadable(string $package): string
    {
        return "The XML element registry of {$package} cannot be read, "
            . 'so the Composer plugin simplesamlphp/composer-xmlprovider-installer cannot have registered it; install it again.';
    }

    /**
     * Lay out a plugin and two providers in the test's directory, one shipping
     * a registry, linked into the plugin's directory or not, and answer each
     * package's install path.
     *
     * @param  bool  $linked
     * @return \Closure(string): ?string
     */
    private function installed(bool $linked): \Closure
    {
        $this->writeScratch('vendor/acme/provider/classes/element.registry.php', self::REGISTRY);
        $this->writeScratch('vendor/acme/bare/composer.json', '{}');
        $this->writeScratch('vendor/plugin/classes/.gitkeep', '');
        $this->writeScratch('vendor/plugin/classes/element.registry.0000.php', "<?php\n\nreturn [];\n");

        if ($linked) {
            $this->writeScratch('vendor/plugin/classes/element.registry.' . sha1('provider') . '.php', self::REGISTRY);
        }

        $paths = [
            PlatformCheck::PLUGIN => $this->scratch('vendor/plugin'),
            'acme/provider'       => $this->scratch('vendor/acme/provider'),
            'acme/bare'           => $this->scratch('vendor/acme/bare'),
        ];

        return static fn (string $package): ?string => $paths[$package] ?? null;
    }
}
