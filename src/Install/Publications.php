<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Install;

use SineMacula\Laravel\Iam\Install\Enums\PublicationKind;

/**
 * Every publishing tag `iam:install` publishes, in its working order (IAM-2.1):
 * member by member, `laravel-authentication`, `laravel-authorization`,
 * `laravel-mfa`, `laravel-sso` and `laravel-audit-log`, the order this package
 * registers them in throughout, then this package's own configuration last,
 * since it bridges them; within a member, its configuration, then its language
 * files, then its migrations. No member's migration has a foreign key to
 * another's, so their order does not matter (IAM-2.4); the order only makes
 * each run's report read the same. `laravel-authentication` ships no language
 * files.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Publications
{
    /** @var string The tag of `laravel-authorization`'s configuration, which the table prefix is written into. */
    public const string AUTHORIZATION_CONFIGURATION = 'authorization-config';

    /** @var string The tag of `laravel-authorization`'s migrations, which read the table names as they run. */
    public const string AUTHORIZATION_MIGRATIONS = 'authorization-migrations';

    /** @var string The namespace of `laravel-authorization`, which each of its migrations names. */
    public const string AUTHORIZATION_NAMESPACE = 'SineMacula\Laravel\Authorization\\';

    /** @var string The tag of `laravel-audit-log`'s configuration, which the capture exclusions are written into. */
    public const string AUDIT_LOG_CONFIGURATION = 'audit-log-config';

    /** @var array<string, array{string, list<\SineMacula\Laravel\Iam\Install\Enums\PublicationKind>}> Each package's tag prefix, its namespace and what it publishes, in order. */
    private const array PACKAGES = [
        'authentication' => ['SineMacula\Laravel\Authentication\\', [PublicationKind::CONFIGURATION, PublicationKind::MIGRATIONS]],
        'authorization'  => [self::AUTHORIZATION_NAMESPACE, [PublicationKind::CONFIGURATION, PublicationKind::LANGUAGE, PublicationKind::MIGRATIONS]],
        'mfa'            => ['SineMacula\Laravel\Mfa\\', [PublicationKind::CONFIGURATION, PublicationKind::LANGUAGE, PublicationKind::MIGRATIONS]],
        'sso'            => ['SineMacula\Laravel\Sso\\', [PublicationKind::CONFIGURATION, PublicationKind::LANGUAGE, PublicationKind::MIGRATIONS]],
        'audit-log'      => ['SineMacula\Laravel\AuditLog\\', [PublicationKind::CONFIGURATION, PublicationKind::LANGUAGE, PublicationKind::MIGRATIONS]],
        'iam'            => ['SineMacula\Laravel\Iam\\', [PublicationKind::CONFIGURATION]],
    ];

    /** @var array<string, string> The suffix of each kind's tag. */
    private const array SUFFIXES = [
        PublicationKind::CONFIGURATION->value => '-config',
        PublicationKind::LANGUAGE->value      => '-lang',
        PublicationKind::MIGRATIONS->value    => '-migrations',
    ];

    /**
     * Every tag to publish, in order.
     *
     * @return list<\SineMacula\Laravel\Iam\Install\Publication>
     */
    public static function all(): array
    {
        $publications = [];

        foreach (self::PACKAGES as $package => [$namespace, $kinds]) {

            foreach ($kinds as $kind) {
                $publications[] = new Publication($package . self::SUFFIXES[$kind->value], $kind, $namespace);
            }
        }

        return $publications;
    }
}
