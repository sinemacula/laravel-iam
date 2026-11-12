<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Iam\Checks\Checker;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `iam:check`: runs every member's check and this package's own, and fails on
 * any problem.
 *
 * Boot's storage refusals stand aside while it runs so it can report them; a
 * member's own boot check still stops it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: self::NAME)]
final class CheckCommand extends Command
{
    /** @var string The command's name. */
    public const string NAME = 'iam:check';

    /** @var string The name and signature of the console command. */
    protected $signature = self::NAME;

    /** @var string The console command description. */
    protected $description = 'Run every member\'s configuration check and laravel-iam\'s own, and fail on any problem';

    /**
     * Run every check and exit on the result.
     *
     * @param  \SineMacula\Laravel\Iam\Checks\Checker  $checker
     * @return int
     */
    public function handle(Checker $checker): int
    {
        return $checker->run($this->output) ? self::SUCCESS : self::FAILURE;
    }
}
