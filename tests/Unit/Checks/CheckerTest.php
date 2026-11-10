<?php

declare(strict_types = 1);

namespace Tests\Unit\Checks;

use Illuminate\Container\Container;
use Illuminate\Contracts\Console\Kernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Checks\Checker;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Fixtures\Checks\ScriptedCheck;

/**
 * Unit tests for running every member's check and this package's own
 * (IAM-10.1): each reported, and the run passing only when every member's
 * command exits successfully and no check of this package's finds a problem.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Checker::class)]
final class CheckerTest extends TestCase
{
    /** @var \Illuminate\Container\Container The container this package's checks are resolved from. */
    private Container $container;

    /** @var \Illuminate\Contracts\Console\Kernel&\Mockery\MockInterface The console the members' commands run through. */
    private Kernel $console;

    /** @var array<string, int|\Throwable> What each member's command exits with, or throws. */
    private array $commands = [];

    /** @var list<mixed> What `Checker::RUNNING` was bound to as each member's command ran. */
    private array $running = [];

    /**
     * Start every test with every member's command registered and exiting
     * successfully, and every check of this package's passing.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
        $this->console   = \Mockery::mock(Kernel::class);
        $this->commands  = array_fill_keys(Checker::MEMBER_COMMANDS, 0);

        $this->console->shouldReceive('all')->andReturnUsing(fn (): array => $this->commands);
        $this->console->shouldReceive('call')->andReturnUsing(function (string $command, array $parameters, BufferedOutput $output): int {
            $outcome         = $this->commands[$command];
            $this->running[] = $this->container->make(Checker::RUNNING);

            if ($outcome instanceof \Throwable) {
                throw $outcome;
            }

            $output->writeln("[{$command}] ran");

            return $outcome;
        });

        foreach (Checker::CHECKS as $check) {
            $this->container->instance($check, new ScriptedCheck(class_basename($check)));
        }
    }

    /**
     * Close Mockery's expectations.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * Every member's command runs in order, then every check of this package's,
     * and the run passes.
     *
     * @return void
     */
    public function testEveryCheckRunsAndTheRunPasses(): void
    {
        [$passed, $output] = $this->runChecker();

        self::assertTrue($passed);
        self::assertSame([
            'authentication:check', '[authentication:check] ran',
            'authorization:check', '[authorization:check] ran',
            'mfa:check', '[mfa:check] ran',
            'sso:check', '[sso:check] ran',
            'audit-log:check', '[audit-log:check] ran',
            'iam',
            '[StorageCheck] OK',
            '[MandatorySeamsCheck] OK',
            '[SsoBridgeFallbackCheck] OK',
            '[ContextNamespacesCheck] OK',
            '[AuditCheck] OK',
            '[SendersCheck] OK',
            '[CrossMemberConfigurationCheck] OK',
            '[PlatformCheck] OK',
            '[SchedulesCheck] OK',
            'Every check passed.',
        ], $output);
    }

    /**
     * `Checker::RUNNING` is `true` while each member's command runs, and
     * `false` once they have, a command that throws included.
     *
     * @return void
     */
    public function testTheMembersCommandsRunMarked(): void
    {
        $this->runChecker();

        self::assertSame(array_fill(0, count(Checker::MEMBER_COMMANDS), true), $this->running);
        self::assertFalse($this->container->make(Checker::RUNNING));

        $this->commands['sso:check'] = new \RuntimeException('SSO stopped.');

        $this->expectExceptionObject(new \RuntimeException('SSO stopped.'));

        try {
            $this->runChecker();
        } finally {
            self::assertFalse($this->container->make(Checker::RUNNING));
        }
    }

    /**
     * A member's command exiting non-zero fails the run, and the rest still
     * run.
     *
     * @return void
     */
    public function testAMemberCommandFailingFailsTheRun(): void
    {
        $this->commands['mfa:check'] = 1;

        [$passed, $output] = $this->runChecker();

        self::assertFalse($passed);
        self::assertContains('[audit-log:check] ran', $output);
        self::assertContains('[StorageCheck] OK', $output);
        self::assertSame('A check failed.', $output[array_key_last($output)]);
    }

    /**
     * A member's command that throws stops the run with its exception.
     *
     * @return void
     */
    public function testAMemberCommandThrowingStopsTheRun(): void
    {
        $this->commands['sso:check'] = new \RuntimeException('SSO stopped.');

        $this->expectExceptionObject(new \RuntimeException('SSO stopped.'));

        $this->runChecker();
    }

    /**
     * Every member's check command.
     *
     * @return iterable<string, array{string}>
     */
    public static function memberCommands(): iterable
    {
        foreach (Checker::MEMBER_COMMANDS as $command) {
            yield $command => [$command];
        }
    }

    /**
     * A member's command that is not registered fails the run, every member's,
     * `laravel-authorization`'s included, and the rest still run.
     *
     * @param  string  $command
     * @return void
     */
    #[DataProvider('memberCommands')]
    public function testAMissingMemberCommandFailsTheRun(string $command): void
    {
        unset($this->commands[$command]);

        [$passed, $output] = $this->runChecker();

        self::assertFalse($passed);
        self::assertContains($command . ' is not registered.', $output);
        self::assertNotContains("[{$command}] ran", $output);

        foreach (array_diff(Checker::MEMBER_COMMANDS, [$command]) as $other) {
            self::assertContains("[{$other}] ran", $output);
        }

        foreach (Checker::CHECKS as $check) {
            self::assertContains('[' . class_basename($check) . '] OK', $output);
        }

        self::assertSame('A check failed.', $output[array_key_last($output)]);
    }

    /**
     * A check's problems fail the run and its notes do not; one that does not
     * apply is reported so; one that cannot be built fails.
     *
     * @return void
     */
    public function testEachCheckIsReported(): void
    {
        $this->container->instance(Checker::CHECKS[0], new ScriptedCheck('noted', [
            static fn (): string => '',
            static fn (): int => 7,
            static fn (): string => 'Worth knowing.',
        ]));
        $this->container->instance(Checker::CHECKS[1], new ScriptedCheck('off', applies: false));

        [$passed, $output] = $this->runChecker();

        self::assertTrue($passed);
        self::assertContains('[noted] note: Worth knowing.', $output);
        self::assertNotContains('[noted] OK', $output);
        self::assertCount(1, array_filter($output, static fn (string $line): bool => str_starts_with($line, '[noted] note:')));
        self::assertContains('[off] not applied', $output);
        self::assertNotContains('[off] OK', $output);

        $this->container->instance(Checker::CHECKS[2], new ScriptedCheck('broken', [
            static function (): never {
                throw new \LogicException('First problem.');
            },
            static fn (): string => 'Still noted.',
            static function (): never {
                throw new \InvalidArgumentException('Second problem.');
            },
        ]));
        $this->container->instance(Checker::CHECKS[3], new ScriptedCheck('unbuilt', failure: new \RuntimeException('Cannot build.')));

        [$passed, $output] = $this->runChecker();

        self::assertFalse($passed);
        self::assertContains('[broken] First problem.', $output);
        self::assertContains('[broken] Second problem.', $output);
        self::assertContains('[broken] note: Still noted.', $output);
        self::assertContains('[' . Checker::CHECKS[3] . '] Cannot build.', $output);
    }

    /**
     * A check that cannot be built fails the run on its own.
     *
     * @return void
     */
    public function testACheckThatCannotBeBuiltFailsTheRun(): void
    {
        $this->container->instance(Checker::CHECKS[0], new ScriptedCheck('unbuilt', failure: new \RuntimeException('Cannot build.')));

        self::assertFalse($this->runChecker()[0]);
    }

    /**
     * Run the checker, and answer whether it passed with the lines it printed.
     *
     * @return array{bool, list<string>}
     */
    private function runChecker(): array
    {
        $output = new BufferedOutput;
        $passed = (new Checker($this->container, $this->console))->run($output);

        return [$passed, array_values(array_filter(explode(PHP_EOL, $output->fetch()), static fn (string $line): bool => $line !== ''))];
    }
}
