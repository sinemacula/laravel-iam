<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Iam\Checks\Checker;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `iam:check`: runs every member's check and this package's own, and exits
 * non-zero on any failure, for use at deploy (IAM-10.1). The checking itself is
 * `Checks\Checker`'s; this command only hands it the output.
 *
 * Boot's refusal of a storage connection mismatch or a member that has not
 * registered stands aside while it runs, so the check reports either instead of
 * stopping before it can. A member whose own boot check refuses its
 * configuration (MFA's, `laravel-authorization`'s) still stops it before it
 * runs, with that member's message and a non-zero exit, which fails closed.
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
