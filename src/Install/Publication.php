<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Install;

use SineMacula\Laravel\Iam\Install\Enums\PublicationKind;

/**
 * One publishing tag `iam:install` publishes: the tag a provider registers its
 * paths under, what the tag copies, and the namespace of the package that
 * registers it, which each of its migrations names, so a copy the application
 * already published is told from a migration of its own that shares a base
 * name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Publication
{
    /**
     * Constructor.
     *
     * @param  string  $tag
     * @param  \SineMacula\Laravel\Iam\Install\Enums\PublicationKind  $kind
     * @param  string  $namespace
     */
    public function __construct(

        /** The tag the provider registers the paths under. */
        public string $tag,

        /** What the tag copies. */
        public PublicationKind $kind,

        /** The namespace of the package that registers the tag, with its trailing separator. */
        public string $namespace,
    ) {}
}
