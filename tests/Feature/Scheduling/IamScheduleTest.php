<?php

declare(strict_types = 1);

namespace Tests\Feature\Scheduling;

use Illuminate\Console\Application as Artisan;
use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Scheduling\IamSchedule;
use Tests\TestCase;

/**
 * Feature tests for registering the members' scheduled work they leave to the
 * application (IAM-2.6): `mfa:prune` and `authorization:prune` daily, SSO's
 * operations schedule while SSO is in use, `audit-log:drain` every minute while
 * audit-log delivers through its outbox, and never audit-log's own seal, sweep,
 * verify or prune.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IamSchedule::class)]
final class IamScheduleTest extends TestCase
{
    /** @var list<string> Audit-log's own scheduled commands, which this package never registers. */
    private const array AUDIT_LOG_OWN = ['audit-log:seal', 'audit-log:seal --sweep', 'audit-log:verify --strict --sweep-first', 'audit-log:prune'];

    /**
     * With SSO not in use and audit-log delivering synchronously, only
     * `mfa:prune` and `authorization:prune` are scheduled, daily.
     *
     * @return void
     */
    public function testOnlyThePrunesAreScheduledWhileSsoIsNotInUseAndDeliveryIsSync(): void
    {
        self::assertSame([['mfa:prune', '0 0 * * *'], ['authorization:prune', '0 0 * * *']], $this->scheduled());
    }

    /**
     * While SSO is in use, its operations schedule registers `sso:prune` once,
     * with the domain rechecks, the metadata refresh and the key expiry report,
     * each at its configured cadence.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSsosOperationsAreScheduledOnceWhileSsoIsInUse(): void
    {
        $this->config()->set('sso.features.saml2', true);
        $this->config()->set('sso.operations.cadence.prune', '7 * * * *');

        self::assertSame([
            ['mfa:prune', '0 0 * * *'],
            ['authorization:prune', '0 0 * * *'],
            ['sso:prune', '7 * * * *'],
            ['sso:domains:recheck', '0 * * * *'],
            ['sso:metadata:refresh', '*/5 * * * *'],
            ['sso:keys:expiring', '0 0 * * *'],
        ], $this->scheduled());
    }

    /**
     * While audit-log delivers through its outbox, the drain is scheduled every
     * minute, until the outbox is empty.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheDrainIsScheduledEveryMinuteWhileDeliveryIsThroughTheOutbox(): void
    {
        $this->config()->set('audit-log.delivery.mode', 'outbox');

        self::assertSame([
            ['mfa:prune', '0 0 * * *'],
            ['authorization:prune', '0 0 * * *'],
            ['audit-log:drain --until-empty', '* * * * *'],
        ], $this->scheduled());
    }

    /**
     * Provide delivery modes that are not audit-log's outbox.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function modesOtherThanTheOutbox(): iterable
    {
        yield 'sync' => ['sync'];
        yield 'unset' => [null];
        yield 'another case' => ['OUTBOX'];
        yield 'padded' => [' outbox'];
        yield 'not text' => [true];
    }

    /**
     * A delivery mode audit-log does not read as its outbox schedules no drain.
     *
     * @param  mixed  $mode
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('modesOtherThanTheOutbox')]
    public function testAnyOtherDeliveryModeSchedulesNoDrain(mixed $mode): void
    {
        $this->config()->set('audit-log.delivery.mode', $mode);

        self::assertSame([['mfa:prune', '0 0 * * *'], ['authorization:prune', '0 0 * * *']], $this->scheduled());
    }

    /**
     * Audit-log's own seal, sweep, verify and prune, which it schedules on the
     * application's schedule itself, are never registered again, whatever is
     * switched on.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAuditLogsOwnSchedulesAreNeverRegisteredAgain(): void
    {
        $this->config()->set('sso.features.oidc', true);
        $this->config()->set('audit-log.delivery.mode', 'outbox');
        $this->config()->set('audit-log.retention.after_days', 30);

        $schedule = $this->app?->make(Schedule::class);

        assert($schedule instanceof Schedule);

        $before = self::commands($schedule);

        Iam::schedule($schedule);

        $after = self::commands($schedule);

        self::assertNotSame([], array_intersect(self::AUDIT_LOG_OWN, $before));

        foreach (self::AUDIT_LOG_OWN as $command) {
            self::assertSame(self::occurrences($command, $before), self::occurrences($command, $after), $command);
        }

        self::assertSame(1, self::occurrences('sso:prune', $after));
        self::assertSame(1, self::occurrences('audit-log:drain --until-empty', $after));
    }

    /**
     * A malformed SSO cadence is SSO's own refusal, thrown as the schedule is
     * built, so a scheduler never starts with it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAMalformedSsoCadenceIsRefusedAsTheScheduleIsBuilt(): void
    {
        $this->config()->set('sso.features.saml2', true);
        $this->config()->set('sso.operations.cadence.prune', 'whenever');

        $this->expectException(\InvalidArgumentException::class);

        $this->scheduled();
    }

    /**
     * Return each task registered on a fresh schedule through the facade, as
     * its command and its cron expression.
     *
     * @return list<array{string, string}>
     */
    private function scheduled(): array
    {
        $schedule = new Schedule;

        Iam::schedule($schedule);

        return array_values(array_map(static fn (Event $event): array => [self::command($event), $event->expression], $schedule->events()));
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Contracts\Config\Repository
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function config(): Repository
    {
        $config = $this->app?->make(Repository::class);

        assert($config instanceof Repository);

        return $config;
    }

    /**
     * Return the Artisan command each of the schedule's tasks runs.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return list<string>
     */
    private static function commands(Schedule $schedule): array
    {
        return array_values(array_map(self::command(...), $schedule->events()));
    }

    /**
     * Return the Artisan command a task runs, without the PHP binary and the
     * Artisan script.
     *
     * @param  \Illuminate\Console\Scheduling\Event  $event
     * @return string
     */
    private static function command(Event $event): string
    {
        $prefix = Artisan::formatCommandString('');

        return substr((string) $event->command, strlen($prefix));
    }

    /**
     * Count how many times a command is scheduled.
     *
     * @param  string  $command
     * @param  list<string>  $commands
     * @return int
     */
    private static function occurrences(string $command, array $commands): int
    {
        return count(array_keys($commands, $command, true));
    }
}
