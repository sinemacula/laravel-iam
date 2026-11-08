<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Iam\Install\AuthorizationTablePrefix;
use SineMacula\Laravel\Iam\Install\Installer;
use SineMacula\Laravel\Iam\Install\InstallReport;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `iam:install`: publishes every member's configuration, language files and
 * migrations, and this package's configuration, writes the values of
 * audit-log's configuration this package needs, offers prefixed names for
 * `laravel-authorization`'s tables, and ends with what the application still
 * owes (IAM-2.1, IAM-2.4). The installation itself is `Install\Installer`'s;
 * this command only reads the prefix, from `--prefix` or, while it can still be
 * written and the command is interactive, by asking, and prints the report.
 *
 * Safe to run twice, and with `--no-interaction` it asks nothing and prefixes
 * nothing unless `--prefix` says so. It exits non-zero when a member has
 * registered none of its publishing tags or a migration's identity is in doubt
 * (a conflict), and with Symfony's `INVALID` code for a prefix that is not one
 * or a configuration it cannot read, with nothing published.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: self::NAME)]
final class InstallCommand extends Command
{
    /** @var string The command's name. */
    public const string NAME = 'iam:install';

    /** @var string The question whether to prefix `laravel-authorization`'s tables. */
    private const string PREFIX_QUESTION = 'Prefix laravel-authorization\'s tables (roles, permissions, policies and the grant tables), whose names may collide with your own?';

    /** @var string The name and signature of the console command. */
    protected $signature = self::NAME . <<<'EOD'

                {--prefix= : Prefix laravel-authorization's table names (for example "authorization_")}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Publish every member\'s configuration, language files and migrations, and say what the application still owes';

    /**
     * Install the suite and report the run.
     *
     * @param  \SineMacula\Laravel\Iam\Install\Installer  $installer
     * @return int
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\PublicationFailedException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function handle(Installer $installer): int
    {
        try {
            $report = $installer->install($this->tablePrefix($installer));
        } catch (\InvalidArgumentException $exception) {
            $this->error($exception->getMessage());

            return self::INVALID;
        }

        $this->report($report);

        return $report->isComplete() ? self::SUCCESS : self::FAILURE;
    }

    /**
     * The prefix for `laravel-authorization`'s tables: the one `--prefix` gives
     * (none when it is given empty, without asking), or, while the prefix can
     * still be written and the command is interactive, the one the application
     * chooses when asked; none otherwise.
     *
     * @param  \SineMacula\Laravel\Iam\Install\Installer  $installer
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function tablePrefix(Installer $installer): ?string
    {
        $option = $this->option('prefix');

        if (is_string($option)) {
            return $option !== '' ? $option : null;
        }

        return $this->askForTablePrefix($installer);
    }

    /**
     * Ask for the prefix for `laravel-authorization`'s tables, while it can
     * still be written and the command is interactive: none when it cannot, or
     * when the application declines one.
     *
     * @param  \SineMacula\Laravel\Iam\Install\Installer  $installer
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function askForTablePrefix(Installer $installer): ?string
    {
        if (!$this->input->isInteractive() || !$installer->offersTablePrefix() || !$this->confirm(self::PREFIX_QUESTION)) {
            return null;
        }

        $prefix = $this->ask('Table prefix', AuthorizationTablePrefix::SUGGESTED);

        return is_string($prefix) ? $prefix : null;
    }

    /**
     * Print what the run did, then what the application still owes.
     *
     * @param  \SineMacula\Laravel\Iam\Install\InstallReport  $report
     * @return void
     */
    private function report(InstallReport $report): void
    {
        foreach ($report->missing as $tag) {
            $this->error("[missing] No provider registered the `{$tag}` tag; nothing was published for it.");
        }

        foreach ($report->published as $path) {
            $this->info('[published] ' . $this->relative($path));
        }

        foreach ($report->kept as $path) {
            $this->line('[kept] ' . $this->relative($path));
        }

        foreach ($report->recognised as $path => $copy) {
            $this->line(sprintf('[recognised] %s, published as %s', basename($path), $this->relative($copy)));
        }

        foreach ($report->written as $key => $value) {
            $this->info("[written] {$key}: {$value}");
        }

        foreach ($report->conflicts as $conflict) {
            $this->error('[conflict] ' . $conflict);
        }

        foreach ($report->notes as $note) {
            $this->line('[note] ' . $note);
        }

        $this->newLine();
        $this->line('Still to do:');

        foreach ($report->owed as $item) {
            $this->line(' - ' . $item);
        }
    }

    /**
     * A path relative to the application's base path, where it is under it.
     *
     * @param  string  $path
     * @return string
     */
    private function relative(string $path): string
    {
        $base = $this->laravel->basePath() . DIRECTORY_SEPARATOR;

        return str_starts_with($path, $base) ? substr($path, strlen($base)) : $path;
    }
}
