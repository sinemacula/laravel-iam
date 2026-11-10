<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Install;

/**
 * What one run of `iam:install` did, and what it leaves the application to do.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InstallReport
{
    /**
     * Constructor.
     *
     * @param  list<string>  $published
     * @param  list<string>  $kept
     * @param  array<string, string>  $recognised
     * @param  array<string, string>  $written
     * @param  list<string>  $conflicts
     * @param  list<string>  $missing
     * @param  list<string>  $owed
     * @param  list<string>  $notes
     */
    public function __construct(

        /** Every file published, by its path. */
        public array $published,

        /** Every configuration or language file already there, left as it was. */
        public array $kept,

        /** Every member migration already published under its base name, by where it would have been published, with the copy found. */
        public array $recognised,

        /** Every configuration key written into a file published in this run, with the value written. */
        public array $written,

        /** Every migration whose identity is in doubt, which the application settles before it migrates. */
        public array $conflicts,

        /** Every publishing tag no provider registered, so nothing was published for it. */
        public array $missing,

        /** What the application still has to do. */
        public array $owed,

        /** What the run found that the application should know, which leaves it complete. */
        public array $notes = [],
    ) {}

    /**
     * Whether the run is complete: every tag was registered, and no migration's
     * identity is in doubt.
     *
     * @return bool
     */
    public function isComplete(): bool
    {
        return $this->missing === [] && $this->conflicts === [];
    }
}
