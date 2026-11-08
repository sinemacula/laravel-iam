<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Install\Enums;

/**
 * What a publishing tag copies into the application, and so how `iam:install`
 * treats a file already there: a configuration file or a language file is left
 * as it is, and a migration is recognised by its base name, whatever its
 * timestamp (IAM-2.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum PublicationKind: string
{
    // A configuration file under `config/`
    case CONFIGURATION = 'configuration';

    // A member's language files under `lang/vendor/`
    case LANGUAGE = 'language';

    // A member's migrations under `database/migrations/`
    case MIGRATIONS = 'migrations';
}
