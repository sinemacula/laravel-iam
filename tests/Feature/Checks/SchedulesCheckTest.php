<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\Iam\Checks\SchedulesCheck;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Scheduling\IamSchedule;
use Tests\Concerns\RunsChecks;
use Tests\TestCase;

/**
 * Feature tests for the schedule check (IAM-2.6): audit-log's own integrity
 * runs switched off with nothing else running them, and the work
 * `Iam::schedule()` registers left off the schedule, each noted without
 * failing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SchedulesCheck::class)]
final class SchedulesCheckTest extends TestCase
{
    use RunsChecks;

    /** @var string The note for MFA's prune left off the schedule. */
    private const string MFA_PRUNE = '`mfa:prune` is not on the schedule; call `Iam::schedule($schedule)` from the application\'s `withSchedule()`.';

    /** @var string The note for `laravel-authorization`'s prune left off the schedule. */
    private const string AUTHORIZATION_PRUNE = '`authorization:prune` is not on the schedule; call `Iam::schedule($schedule)` from the application\'s `withSchedule()`.';

    /**
     * Audit-log's own runs are on the schedule as it ships; MFA's prune and
     * `laravel-authorization`'s are noted until `Iam::schedule()` registers
     * them. Nothing fails.
     *
     * @return void
     */
    public function testThePrunesAreNotedUntilThePackageSchedulesThem(): void
    {
        $checks = $this->check()->checks();

        self::assertSame([], self::problems($checks));
        self::assertSame([self::MFA_PRUNE, self::AUTHORIZATION_PRUNE], self::notes($checks));
        self::assertTrue($this->check()->applies());
        self::assertSame('schedule', $this->check()->subject());

        $this->schedulePackage();

        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * Each of audit-log's integrity runs switched off is noted while nothing
     * else on the schedule runs it, and not once the application schedules it
     * itself.
     *
     * @return void
     */
    public function testAuditLogsRunsSwitchedOffAreNotedUntilSomethingRunsThem(): void
    {
        $config = $this->app?->make('config');

        $config?->set('audit-log.integrity.seal.schedule', null);
        $config?->set('audit-log.integrity.seal.sweep_schedule', '');
        $config?->set('audit-log.integrity.verify.schedule', null);

        $this->schedulePackage();

        self::assertSame([
            'audit-log schedules its own `audit-log:seal` only while its setting gives a cron expression, and no event on the schedule runs it.',
            'audit-log schedules its own `audit-log:seal --sweep` only while its setting gives a cron expression, and no event on the schedule runs it.',
            'audit-log schedules its own `audit-log:verify` only while its setting gives a cron expression, and no event on the schedule runs it.',
        ], self::notes($this->check()->checks()));

        $schedule = $this->schedule();

        $schedule->command('audit-log:seal --sweep')->daily();

        $notes = self::notes($this->check()->checks());

        self::assertCount(2, $notes);
        self::assertStringContainsString('`audit-log:seal` only', $notes[0]);
        self::assertStringContainsString('`audit-log:verify`', $notes[1]);

        $schedule->command('audit-log:seal')->everyFiveMinutes();
        $schedule->command('audit-log:verify --strict')->daily();
        $schedule->call(static fn (): null => null)->daily();

        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * Audit-log's prune is scheduled only while its retention can delete
     * entries: kept forever, its prune switched off is not noted; kept for a
     * number of days, it is noted while nothing else on the schedule runs it,
     * and not once the application schedules it itself.
     *
     * @return void
     */
    public function testAuditLogsPruneSwitchedOffIsNotedWhileItsRetentionCanDelete(): void
    {
        $config = $this->app?->make('config');

        $config?->set('audit-log.retention.schedule', null);

        $this->schedulePackage();

        self::assertSame([], self::notes($this->check()->checks()));

        $config?->set('audit-log.retention.after_days', 30);

        self::assertSame([], self::problems($this->check()->checks()));
        self::assertSame([
            'audit-log schedules its own `audit-log:prune` only while `audit-log.retention.schedule` gives a cron expression, '
                . 'and no event on the schedule runs it, though its retention can delete entries.',
        ], self::notes($this->check()->checks()));

        $this->schedule()->command('audit-log:prune')->daily();

        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * Audit-log's prune on its own schedule, while its retention can delete
     * entries, is not noted.
     *
     * @return void
     */
    public function testAuditLogsPruneOnItsOwnScheduleIsNotNoted(): void
    {
        $this->app?->make('config')->set('audit-log.retention.after_days', 30);

        $this->schedulePackage();

        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * A bound retention policy other than audit-log's configured one can delete
     * whatever the settings say, so its prune switched off is noted.
     *
     * @return void
     */
    public function testAuditLogsPruneSwitchedOffUnderABoundPolicyIsNoted(): void
    {
        $app = $this->app;

        assert($app !== null);

        $app->make('config')->set('audit-log.retention.schedule', null);
        $app->singleton(RetentionPolicy::class, static fn (): RetentionPolicy => new class implements RetentionPolicy {
            /**
             * The policy's version.
             *
             * @return string
             */
            #[\Override]
            public function version(): string
            {
                return 'v1';
            }

            /**
             * Every entry is kept for a day.
             *
             * @param  string  $category
             * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
             * @return int
             */
            #[\Override]
            public function retainFor(string $category, ?Reference $tenant): int
            {
                return 1;
            }

            /**
             * Nothing must be preserved.
             *
             * @param  string  $category
             * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
             * @return ?int
             */
            #[\Override]
            public function preserveFor(string $category, ?Reference $tenant): ?int
            {
                return null;
            }
        });

        $this->schedulePackage();

        $notes = self::notes($this->check()->checks());

        self::assertCount(1, $notes);
        self::assertStringContainsString('though its retention can delete entries', $notes[0]);
    }

    /**
     * Rows of retention audit-log cannot judge, with the class of what judging
     * it throws: a malformed setting, and a bound policy that cannot be
     * resolved.
     *
     * @return iterable<string, array{\Closure(\Illuminate\Foundation\Application): void, class-string<\Throwable>}>
     */
    public static function unjudgedRetentions(): iterable
    {
        yield 'malformed setting' => [static function (Application $app): void {
            $app->make('config')->set('audit-log.retention.after_days', 'a month');
        }, \InvalidArgumentException::class];

        yield 'unresolvable policy' => [static function (Application $app): void {
            $app->singleton(RetentionPolicy::class, static fn (): never => throw new \RuntimeException('secret-free'));
        }, \RuntimeException::class];
    }

    /**
     * Retention audit-log cannot judge, with its prune switched off, is noted
     * with the cause by its class, never its message, and without failing the
     * run; once something on the schedule runs the prune it is not.
     *
     * @param  \Closure(\Illuminate\Foundation\Application): void  $arrange
     * @param  class-string<\Throwable>  $cause
     * @return void
     */
    #[DataProvider('unjudgedRetentions')]
    public function testAuditLogsPruneIsNotedWithItsCauseWhenRetentionCannotBeJudged(\Closure $arrange, string $cause): void
    {
        $app = $this->app;

        assert($app instanceof Application);

        $app->make('config')->set('audit-log.retention.schedule', null);

        $arrange($app);

        $this->schedulePackage();

        self::assertSame([], self::problems($this->check()->checks()));
        self::assertSame([
            'audit-log cannot judge whether its retention can delete entries (' . $cause . '), and no event on the schedule runs `audit-log:prune`; '
                . 'audit-log schedules it only while `audit-log.retention.schedule` gives a cron expression.',
        ], self::notes($this->check()->checks()));

        $this->schedule()->command('audit-log:prune')->daily();

        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * While SSO is in use, its prune is noted until it is on the schedule,
     * which SSO's operations schedule, called by `Iam::schedule()`, puts it.
     *
     * @return void
     */
    public function testSsosPruneIsNotedWhileSsoIsInUse(): void
    {
        $this->app?->make('config')->set('sso.features.saml2', true);

        $note = '`sso:prune` is not on the schedule; call `Iam::schedule($schedule)` from the application\'s `withSchedule()`.';

        self::assertSame([self::MFA_PRUNE, self::AUTHORIZATION_PRUNE, $note], self::notes($this->check()->checks()));

        $this->schedulePackage();

        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * Rows of SSO's prune cadence switched off: `null` or empty.
     *
     * @return iterable<string, array{?string}>
     */
    public static function switchedOffCadences(): iterable
    {
        yield 'null' => [null];
        yield 'empty' => [''];
    }

    /**
     * While SSO is in use with its prune cadence switched off, SSO's operations
     * schedule hands `sso:prune` to the application, so `Iam::schedule()`
     * registers SSO's other tasks but not the prune: the note gives that cause,
     * not the call already made, and goes once the application schedules the
     * prune itself.
     *
     * @param  ?string  $cadence
     * @return void
     */
    #[DataProvider('switchedOffCadences')]
    public function testSsosPruneSwitchedOffIsNotedWithItsCause(?string $cadence): void
    {
        $config = $this->app?->make('config');

        $config?->set('sso.features.saml2', true);
        $config?->set('sso.operations.cadence.prune', $cadence);

        $this->schedulePackage();

        $note = 'SSO\'s operations schedule runs `sso:prune` only while `sso.operations.cadence.prune` gives a cron expression, '
            . 'and no event on the schedule runs it; set the cadence, or schedule `sso:prune` from the application\'s `withSchedule()`.';

        self::assertSame([], self::problems($this->check()->checks()));
        self::assertSame([$note], self::notes($this->check()->checks()));

        $this->schedule()->command('sso:prune')->hourly();

        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * While audit-log delivers through its outbox, its drain is noted until it
     * is on the schedule.
     *
     * @return void
     */
    public function testTheDrainIsNotedWhileTheOutboxIsOn(): void
    {
        $this->app?->make('config')->set(IamSchedule::DELIVERY_MODE, 'outbox');

        $note = '`audit-log:drain --until-empty` is not on the schedule; call `Iam::schedule($schedule)` from the application\'s `withSchedule()`.';

        self::assertSame([self::MFA_PRUNE, self::AUTHORIZATION_PRUNE, $note], self::notes($this->check()->checks()));

        $this->schedulePackage();

        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * A schedule that cannot be built, as `Iam::schedule()` hooked into its
     * resolution from `withSchedule()` builds it with a malformed SSO cadence,
     * is one problem naming the cause, and no run is noted missing from what
     * was built of it.
     *
     * @return void
     */
    public function testAScheduleThatCannotBeBuiltIsOneProblemNamingItsCause(): void
    {
        $app = $this->app;

        assert($app !== null);

        $config = $app->make('config');

        $config->set('sso.features.saml2', true);
        $config->set('sso.operations.cadence.prune', 'whenever');
        $config->set(IamSchedule::DELIVERY_MODE, 'outbox');

        $app->afterResolving(Schedule::class, static function (Schedule $schedule): void {
            Iam::schedule($schedule);
        });

        [$problems, $notes] = self::findings($this->check()->checks());

        self::assertSame([
            'The application\'s schedule cannot be built, so no run on it is checked: '
                . 'sso.operations.cadence.prune must be a cron expression, or null or empty for none.',
        ], $problems);
        self::assertSame([], $notes);
    }

    /**
     * Register what `Iam::schedule()` registers on the application's schedule.
     *
     * @return void
     */
    private function schedulePackage(): void
    {
        $this->app?->make(IamSchedule::class)->register($this->schedule());
    }

    /**
     * The application's schedule.
     *
     * @return \Illuminate\Console\Scheduling\Schedule
     */
    private function schedule(): Schedule
    {
        $schedule = $this->app?->make(Schedule::class);

        assert($schedule instanceof Schedule);

        return $schedule;
    }

    /**
     * The check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\SchedulesCheck
     */
    private function check(): SchedulesCheck
    {
        $check = $this->app?->make(SchedulesCheck::class);

        assert($check instanceof SchedulesCheck);

        return $check;
    }
}
