<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `iam:check`: runs the members' check commands, then this package's checks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Checker
{
    /** @var list<string> The members' check commands, in the order they run. */
    public const array MEMBER_COMMANDS = ['authentication:check', 'authorization:check', 'mfa:check', 'sso:check', 'audit-log:check'];

    /** @var list<class-string<\SineMacula\Laravel\Iam\Checks\Contracts\Check>> This package's checks, in the order they run. */
    public const array CHECKS = [
        StorageCheck::class,
        MandatorySeamsCheck::class,
        SsoBridgeCheck::class,
        ContextNamespacesCheck::class,
        AuditCheck::class,
        CrossMemberConfigurationCheck::class,
        SchedulesCheck::class,
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Console\Kernel  $console
     */
    public function __construct(

        /** The container this package's checks are resolved from. */
        private Container $container,

        /** The console the members' check commands run through. */
        private Kernel $console,
    ) {}

    /**
     * Run every member's check, then this package's, and answer whether all
     * pass.
     *
     * @param  \Symfony\Component\Console\Output\OutputInterface  $output
     * @return bool
     */
    public function run(OutputInterface $output): bool
    {
        $passed = $this->runCommands($output);

        $output->writeln('<comment>iam</comment>');

        foreach (self::CHECKS as $check) {
            $passed = $this->runCheck($check, $output) && $passed;
        }

        $output->writeln($passed ? '<info>Every check passed.</info>' : '<error>A check failed.</error>');

        return $passed;
    }

    /**
     * Run the members' check commands and answer whether all pass.
     *
     * @param  \Symfony\Component\Console\Output\OutputInterface  $output
     * @return bool
     */
    private function runCommands(OutputInterface $output): bool
    {
        $passed   = true;
        $commands = $this->console->all();

        foreach (self::MEMBER_COMMANDS as $command) {

            if (!array_key_exists($command, $commands)) {
                $passed = false;

                $output->writeln(sprintf('<comment>%s</comment> is not registered.', $command));

                continue;
            }

            $passed = $this->runCommand($command, $output) && $passed;
        }

        return $passed;
    }

    /**
     * Run a member's check command and answer whether it succeeded.
     *
     * @param  string  $command
     * @param  \Symfony\Component\Console\Output\OutputInterface  $output
     * @return bool
     */
    private function runCommand(string $command, OutputInterface $output): bool
    {
        $output->writeln(sprintf('<comment>%s</comment>', $command));

        return $this->console->call($command, [], $output) === 0;
    }

    /**
     * Run one of this package's checks and answer whether it found no problem.
     *
     * @param  class-string<\SineMacula\Laravel\Iam\Checks\Contracts\Check>  $class
     * @param  \Symfony\Component\Console\Output\OutputInterface  $output
     * @return bool
     */
    private function runCheck(string $class, OutputInterface $output): bool
    {
        try {
            $check = $this->container->make($class);

            if (!$check->applies()) {
                $output->writeln(sprintf('[%s] not applied', $check->subject()));

                return true;
            }

            $closures = $check->checks();
        } catch (\Throwable $exception) {
            $output->writeln(sprintf('[%s] %s', $class, $exception->getMessage()));

            return false;
        }

        return self::report($check->subject(), $closures, $output) === 0;
    }

    /**
     * Run a check's closures, report its problems and notes, and count
     * problems.
     *
     * @param  string  $subject
     * @param  list<\Closure(): mixed>  $closures
     * @param  \Symfony\Component\Console\Output\OutputInterface  $output
     * @return int
     */
    private static function report(string $subject, array $closures, OutputInterface $output): int
    {
        $problems = [];
        $notes    = [];

        foreach ($closures as $closure) {

            try {
                $note = $closure();
            } catch (\Throwable $exception) {
                $problems[] = $exception->getMessage();

                continue;
            }

            if (!is_string($note) || $note === '') {
                continue;
            }

            $notes[] = $note;
        }

        foreach ($problems as $problem) {
            $output->writeln(sprintf('<error>[%s]</error> %s', $subject, $problem));
        }

        foreach ($notes as $note) {
            $output->writeln(sprintf('[%s] note: %s', $subject, $note));
        }

        if ($problems === [] && $notes === []) {
            $output->writeln(sprintf('[%s] OK', $subject));
        }

        return count($problems);
    }
}
