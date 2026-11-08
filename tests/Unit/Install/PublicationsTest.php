<?php

declare(strict_types = 1);

namespace Tests\Unit\Install;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Install\Enums\PublicationKind;
use SineMacula\Laravel\Iam\Install\Publication;
use SineMacula\Laravel\Iam\Install\Publications;

/**
 * Unit tests for the publishing tags `iam:install` publishes and their working
 * order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Publications::class)]
#[CoversClass(Publication::class)]
final class PublicationsTest extends TestCase
{
    /**
     * Every member's tags are published member by member, configuration, then
     * language files, then migrations, and this package's configuration last.
     *
     * @return void
     */
    public function testEveryTagIsPublishedInItsWorkingOrder(): void
    {
        self::assertSame([
            ['authentication-config', PublicationKind::CONFIGURATION],
            ['authentication-migrations', PublicationKind::MIGRATIONS],
            ['authorization-config', PublicationKind::CONFIGURATION],
            ['authorization-lang', PublicationKind::LANGUAGE],
            ['authorization-migrations', PublicationKind::MIGRATIONS],
            ['mfa-config', PublicationKind::CONFIGURATION],
            ['mfa-lang', PublicationKind::LANGUAGE],
            ['mfa-migrations', PublicationKind::MIGRATIONS],
            ['sso-config', PublicationKind::CONFIGURATION],
            ['sso-lang', PublicationKind::LANGUAGE],
            ['sso-migrations', PublicationKind::MIGRATIONS],
            ['audit-log-config', PublicationKind::CONFIGURATION],
            ['audit-log-lang', PublicationKind::LANGUAGE],
            ['audit-log-migrations', PublicationKind::MIGRATIONS],
            ['iam-config', PublicationKind::CONFIGURATION],
        ], array_map(static fn (Publication $publication): array => [$publication->tag, $publication->kind], Publications::all()));
    }

    /**
     * Each tag carries the namespace of the package that registers it, which
     * each of its migrations names.
     *
     * @return void
     */
    public function testEachTagCarriesItsPackagesNamespace(): void
    {
        $namespaces = [];

        foreach (Publications::all() as $publication) {
            $namespaces[$publication->tag] = $publication->namespace;
        }

        self::assertSame('SineMacula\Laravel\Authentication\\', $namespaces['authentication-migrations']);
        self::assertSame(Publications::AUTHORIZATION_NAMESPACE, $namespaces['authorization-migrations']);
        self::assertSame('SineMacula\Laravel\Authorization\\', Publications::AUTHORIZATION_NAMESPACE);
        self::assertSame('SineMacula\Laravel\Mfa\\', $namespaces['mfa-migrations']);
        self::assertSame('SineMacula\Laravel\Sso\\', $namespaces['sso-migrations']);
        self::assertSame('SineMacula\Laravel\AuditLog\\', $namespaces['audit-log-migrations']);
        self::assertSame('SineMacula\Laravel\Iam\\', $namespaces['iam-config']);
    }

    /**
     * The tags the installer writes into, or reads the table names from, are
     * among the tags published.
     *
     * @return void
     */
    public function testTheTagsWrittenIntoArePublished(): void
    {
        $tags = array_map(static fn (Publication $publication): string => $publication->tag, Publications::all());

        self::assertContains(Publications::AUTHORIZATION_CONFIGURATION, $tags);
        self::assertContains(Publications::AUTHORIZATION_MIGRATIONS, $tags);
        self::assertContains(Publications::AUDIT_LOG_CONFIGURATION, $tags);
    }
}
