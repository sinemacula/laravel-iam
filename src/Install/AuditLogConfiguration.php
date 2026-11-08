<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Install;

use Illuminate\Filesystem\Filesystem;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;

/**
 * The values of `laravel-audit-log`'s configuration this package needs, written
 * into the configuration file `iam:install` has just published (decision Q5
 * (a), IAM-2.5): every `jwt` and `api_key` guard in
 * `capture.laravel.except_guards`, so nothing the suite records is recorded
 * twice, and `definitions.require_registered` on, so a code no definition
 * registers is refused rather than recorded unchecked.
 *
 * `except_guards` reads no environment variable, so its list is written as it
 * is, each guard a single-quoted PHP string; `require_registered` is written as
 * the default of the variable the file reads, so the variable still wins where
 * the application sets one, as `iam:check` then reports. Gate capture already
 * defaults off in the published file, so nothing is written for it. Each value
 * is written only where the published file still holds audit-log's own default,
 * matched exactly once, and every key written is returned, so one audit-log has
 * reshaped is reported for the application to set rather than guessed at. A
 * configuration file the application had already published is never written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuditLogConfiguration
{
    /** @var string Audit-log's own default of the excluded guards: none. */
    private const string EXCEPT_GUARDS = '/(\'except_guards\'\s*=>\s*)\[\]/';

    /** @var string Audit-log's own default of refusing a code no definition registers: off. */
    private const string REQUIRE_REGISTERED = '/(env\(\s*\'AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED\'\s*,\s*)false(\s*\))/';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Filesystem\Filesystem  $files
     */
    public function __construct(

        /** The filesystem the configuration file is read from and written to. */
        private Filesystem $files,
    ) {}

    /**
     * Write the guards to exclude and turn the refusal of unregistered codes on
     * in audit-log's published configuration file, and return the keys written.
     * An empty list of guards needs no writing: audit-log's default already
     * excludes none.
     *
     * @param  string  $file
     * @param  list<string>  $exceptGuards
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function write(string $file, array $exceptGuards): array
    {
        $contents = $this->files->get($file);
        $written  = [];

        if ($exceptGuards !== []) {
            $list     = '[' . implode(', ', array_map(static fn (string $guard): string => self::quote($guard), $exceptGuards)) . ']';
            $contents = self::replaceOnce(self::EXCEPT_GUARDS, $list, $contents, CaptureExclusions::EXCEPT_GUARDS_KEY, $written);
        }

        $contents = self::replaceOnce(self::REQUIRE_REGISTERED, 'true', $contents, AuditSettings::REQUIRE_REGISTERED, $written);

        if ($written !== []) {
            $this->files->put($file, $contents);
        }

        return $written;
    }

    /**
     * Replace the value of the one match of a default, keeping what surrounds
     * it, and record its key as written; a default found other than once is
     * left as it is.
     *
     * @param  string  $pattern
     * @param  string  $value
     * @param  string  $contents
     * @param  string  $key
     * @param  list<string>  $written
     * @return string
     */
    private static function replaceOnce(string $pattern, string $value, string $contents, string $key, array &$written): string
    {
        if (preg_match_all($pattern, $contents) !== 1) {
            return $contents;
        }

        $written[] = $key;

        return (string) preg_replace_callback($pattern, static fn (array $match): string => $match[1] . $value . ($match[2] ?? ''), $contents);
    }

    /**
     * Quote a guard's name as a single-quoted PHP string.
     *
     * @param  string  $guard
     * @return string
     */
    private static function quote(string $guard): string
    {
        return '\'' . str_replace(['\\', '\''], ['\\\\', '\\\''], $guard) . '\'';
    }
}
