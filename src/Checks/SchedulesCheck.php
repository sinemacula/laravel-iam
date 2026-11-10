<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\AuditLog\Console\IntegritySchedule;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Scheduling\IamSchedule;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Sso\Operations\OperationsSettings;

/**
 * The scheduled work the members need is on the application's schedule
 * (IAM-2.6), reported as notes: a run the schedule leaves out may be started by
 * other means (a cron entry of the server's, another scheduler), which no check
 * can see, so no run left out fails the run. A schedule that cannot be built at
 * all (a malformed SSO cadence, thrown by SSO's operations schedule as
 * `Iam::schedule()` registers it) is the one failure, naming the cause, since
 * the scheduler would not start either; no run is then noted missing from what
 * was built of it. It is reported only when the schedule is first built inside
 * `iam:check`: where the application resolves it while the console bootstraps
 * (Laravel's `Schedule` facade in `routes/console.php`), the `withSchedule()`
 * callback runs as the console starts, and SSO's exception stops every console
 * command, this one included, before any check runs.
 *
 * - Audit-log schedules its own sealing, sweep, strict verification and prune,
 *   each at the cron expression its setting gives, and nothing when the setting
 *   is switched off (`null` or empty); this package never registers them again.
 *   Each is noted when no event on the schedule runs it: switched off, with
 *   nothing else running it. The prune is scheduled only when its retention can
 *   delete something, so it is noted only then, as audit-log's
 *   `IntegritySchedule::prunes()` judges it; where audit-log cannot judge it (a
 *   malformed retention setting, or a bound retention policy that cannot be
 *   resolved), the prune is noted with that cause, naming the exception's class
 *   and never its message.
 * - The work this package's `Iam::schedule()` registers (`IamSchedule`): MFA's
 *   prune and `laravel-authorization`'s always, SSO's prune while SSO is in use
 *   (its operations schedule registers it), and audit-log's drain while its
 *   delivery runs through its outbox. Each is noted when no event runs it, with
 *   the call that registers it; SSO's prune, when its cadence
 *   (`sso.operations.cadence.prune`, read as SSO's
 *   `OperationsSettings::cadence()` reads it) is switched off (`null` or
 *   empty), is noted with that cause instead, since SSO's operations schedule
 *   then hands the command to the application and calling `Iam::schedule()`
 *   would change nothing.
 *
 * The schedule is the application's own, resolved from the container with every
 * event registered on it as it is resolved (audit-log's, the application's
 * `withSchedule()` and `routes/console.php`), as `schedule:list` reads it. A
 * command is found on it by its name among the words of each event's command
 * line.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SchedulesCheck implements Check
{
    /** @var string Audit-log's sealing, and with the option, its sweep. */
    private const string SEAL = 'audit-log:seal';

    /** @var string The option that makes audit-log's sealing its sweep. */
    private const string SWEEP = '--sweep';

    /** @var string Audit-log's verification. */
    private const string VERIFY = 'audit-log:verify';

    /** @var string Audit-log's prune. */
    private const string AUDIT_PRUNE = 'audit-log:prune';

    /** @var string The key of audit-log's prune schedule. */
    private const string AUDIT_PRUNE_SCHEDULE = 'audit-log.retention.schedule';

    /** @var string The note of audit-log's prune switched off while its retention can delete, with nothing else running it. */
    private const string AUDIT_PRUNE_OFF = 'audit-log schedules its own `%s` only while `%s` gives a cron expression, and no event on the schedule runs it, '
        . 'though its retention can delete entries.';

    /** @var string The note of audit-log's prune off the schedule while audit-log cannot judge whether its retention can delete. */
    private const string AUDIT_PRUNE_UNJUDGED = 'audit-log cannot judge whether its retention can delete entries (%s), and no event on the schedule runs `%s`; '
        . 'audit-log schedules it only while `%s` gives a cron expression.';

    /** @var string SSO's prune. */
    private const string SSO_PRUNE = 'sso:prune';

    /** @var string The task SSO's operations schedule runs its prune as. */
    private const string SSO_PRUNE_TASK = 'prune';

    /** @var string The key of SSO's prune cadence. */
    private const string SSO_PRUNE_CADENCE = 'sso.operations.cadence.' . self::SSO_PRUNE_TASK;

    /** @var string The note of SSO's prune switched off, with nothing else running it. */
    private const string SSO_PRUNE_OFF = 'SSO\'s operations schedule runs `%s` only while `%s` gives a cron expression, and no event on the schedule runs it; '
        . 'set the cadence, or schedule `%s` from the application\'s `withSchedule()`.';

    /** @var string Why a schedule that cannot be built is refused. */
    private const string UNBUILT = 'The application\'s schedule cannot be built, so no run on it is checked: %s';

    /** @var string The outbox delivery mode. */
    private const string OUTBOX = 'outbox';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container the application's schedule is resolved from. */
        private Container $container,

        /** The configuration SSO's use and audit-log's delivery mode are read from. */
        private Repository $config,
    ) {}

    /**
     * The subject the findings are reported under.
     *
     * @return string
     */
    #[\Override]
    public function subject(): string
    {
        return 'schedule';
    }

    /**
     * The check always applies.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * The schedule built, then a note for each of audit-log's integrity runs
     * and its prune no event runs, then for each run of `Iam::schedule()`'s no
     * event runs. The first closure builds the schedule once and hands its
     * events to the rest through `$events`; a schedule that cannot be built is
     * its one problem, and the rest note nothing.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $own    = 'audit-log schedules its own `%s` only while its setting gives a cron expression, and no event on the schedule runs it.';
        $iam    = '`%s` is not on the schedule; call `Iam::schedule($schedule)` from the application\'s `withSchedule()`.';
        $events = null;

        $checks = [
            function () use (&$events): void {
                $events = $this->events();
            },
            self::noteUnless($events, self::SEAL, false, sprintf($own, self::SEAL)),
            self::noteUnless($events, self::SEAL, true, sprintf($own, self::SEAL . ' ' . self::SWEEP)),
            self::noteUnless($events, self::VERIFY, null, sprintf($own, self::VERIFY)),
            self::noteUnless($events, self::AUDIT_PRUNE, null, $this->auditPruneNote(...)),
            self::noteUnless($events, IamSchedule::MFA_PRUNE, null, sprintf($iam, IamSchedule::MFA_PRUNE)),
            self::noteUnless($events, IamSchedule::AUTHORIZATION_PRUNE, null, sprintf($iam, IamSchedule::AUTHORIZATION_PRUNE)),
        ];

        if (SsoSeams::isInUse($this->config)) {
            $checks[] = self::noteUnless($events, self::SSO_PRUNE, null, $this->ssoPruneNote($iam));
        }

        if ($this->config->get(IamSchedule::DELIVERY_MODE) === self::OUTBOX) {
            $checks[] = self::noteUnless($events, IamSchedule::AUDIT_DRAIN, null, sprintf($iam, IamSchedule::AUDIT_DRAIN));
        }

        return $checks;
    }

    /**
     * The events of the application's schedule, built as it is resolved; a
     * schedule whose building throws (a malformed SSO cadence, say, as
     * `Iam::schedule()` registers SSO's operations from the application's
     * `withSchedule()`) is refused, naming the cause. The container keeps the
     * schedule as it was when the building threw, missing everything that would
     * have been registered after, so the notes read nothing from it.
     *
     * @return array<int, \Illuminate\Console\Scheduling\Event>
     *
     * @throws \LogicException
     */
    private function events(): array
    {
        try {
            $schedule = $this->container->make(Schedule::class);
        } catch (\Throwable $exception) {
            throw new \LogicException(sprintf(self::UNBUILT, $exception->getMessage()), previous: $exception);
        }

        return $schedule->events();
    }

    /**
     * The note for audit-log's prune left off the schedule: nothing while its
     * retention cannot delete anything, the setting that switched it off while
     * it can, and the cause, by its class, when audit-log cannot judge it.
     *
     * @return ?string
     */
    private function auditPruneNote(): ?string
    {
        try {
            $prunes = $this->container->make(IntegritySchedule::class)->prunes();
        } catch (\Throwable $exception) {
            return sprintf(self::AUDIT_PRUNE_UNJUDGED, $exception::class, self::AUDIT_PRUNE, self::AUDIT_PRUNE_SCHEDULE);
        }

        return $prunes ? sprintf(self::AUDIT_PRUNE_OFF, self::AUDIT_PRUNE, self::AUDIT_PRUNE_SCHEDULE) : null;
    }

    /**
     * The note for SSO's prune left off the schedule: its cadence switched off,
     * which `Iam::schedule()` cannot change, or else the call that registers
     * it.
     *
     * @param  string  $iam
     * @return string
     */
    private function ssoPruneNote(string $iam): string
    {
        $cadence = $this->config->get(self::SSO_PRUNE_CADENCE, OperationsSettings::TASKS[self::SSO_PRUNE_TASK]);

        return $cadence === null || $cadence === ''
            ? sprintf(self::SSO_PRUNE_OFF, self::SSO_PRUNE, self::SSO_PRUNE_CADENCE, self::SSO_PRUNE)
            : sprintf($iam, self::SSO_PRUNE);
    }

    /**
     * A closure answering the note given unless an event of the schedule runs
     * the command, and nothing while the schedule has not been built. `$events`
     * is the variable the first of the checks sets once it has built the
     * schedule, read when the closure runs. A note given as a closure is
     * answered only then, and may itself answer nothing.
     *
     * @param  ?array<int, \Illuminate\Console\Scheduling\Event>  $events
     * @param  string  $command
     * @param  ?bool  $sweep
     * @param  \Closure(): ?string|string  $note
     * @return \Closure(): ?string
     */
    private static function noteUnless(?array &$events, string $command, ?bool $sweep, \Closure|string $note): \Closure
    {
        return static function () use (&$events, $command, $sweep, $note): ?string {

            if ($events === null || self::runs($events, $command, $sweep)) {
                return null;
            }

            return $note instanceof \Closure ? $note() : $note;
        };
    }

    /**
     * Whether one of the events runs the command, with or without the sweep
     * option when that is asked, and either way when it is not.
     *
     * @param  array<int, \Illuminate\Console\Scheduling\Event>  $events
     * @param  string  $command
     * @param  ?bool  $sweep
     * @return bool
     */
    private static function runs(array $events, string $command, ?bool $sweep): bool
    {
        $name = strtok($command, ' ');

        foreach ($events as $event) {

            $words = self::words($event);

            if (in_array($name, $words, true) && ($sweep === null || in_array(self::SWEEP, $words, true) === $sweep)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The words of the event's command line: Laravel quotes the PHP binary and
     * Artisan, never the command's own name or options.
     *
     * @param  \Illuminate\Console\Scheduling\Event  $event
     * @return list<string>
     */
    private static function words(Event $event): array
    {
        return preg_split('/\s+/', (string) $event->command) ?: [];
    }
}
