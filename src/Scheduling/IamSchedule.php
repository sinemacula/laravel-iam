<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Scheduling;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\Mfa\Console\PruneCommand;
use SineMacula\Laravel\Sso\Operations\OperationsSchedule;

/**
 * The members' scheduled work they leave to the application, registered on its
 * schedule in one call (IAM-2.6): `mfa:prune` daily, as MFA's lifecycle guide
 * schedules it; `authorization:prune` daily, as `laravel-authorization`'s
 * README schedules it, removing the grants that have expired and those of
 * grantees and records that are gone (an expired grant already stops counting
 * at its expiry, so the prune keeps the grant tables small rather than making a
 * check correct); SSO's operations schedule (`sso:prune`, the domain rechecks,
 * the metadata refresh, whose jobs run on `sso.metadata.queue`, and the key
 * expiry report, at `sso.operations.cadence.*`), which registers nothing while
 * SSO is not in use; and, while `audit-log.delivery.mode` is `outbox`,
 * `audit-log:drain --until-empty` every minute, as audit-log's README schedules
 * it.
 *
 * Audit-log schedules its own seal, sweep, verify and prune as the console
 * resolves the schedule, so none of them is registered again here; `iam:check`
 * reports one switched off with nothing else running it.
 *
 * No task is given a cache mutex (`withoutOverlapping()`, `onOneServer()`):
 * each command is safe to run on several servers at once, by what it does in
 * the database, as SSO's operations schedule promises for its own, so a stale
 * mutex can never suppress maintenance; SSO's `sso.operations.cache_mutexes`
 * still opts its own tasks in. A malformed SSO cadence is SSO's own
 * `InvalidArgumentException`, thrown as the schedule is built, so a scheduler
 * never starts with it, nor, while the schedule is resolved as the console
 * bootstraps, any console command; it is left as it is, as catching it here
 * would drop the rest of SSO's operations without a word. A delivery mode
 * audit-log does not read as `outbox` schedules no drain, and audit-log refuses
 * it when a record is captured and reports it in `audit-log:check`.
 *
 * Every value is read when the schedule is built, never kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IamSchedule
{
    /** @var string MFA's pruning of the records that stopped being usable. */
    public const string MFA_PRUNE = PruneCommand::NAME;

    /** @var string `laravel-authorization`'s pruning of the grants that no longer count, which names no constant of its own. */
    public const string AUTHORIZATION_PRUNE = 'authorization:prune';

    /** @var string Audit-log's delivery of its outbox, batch after batch until none is left. */
    public const string AUDIT_DRAIN = 'audit-log:drain --until-empty';

    /** @var string The key of audit-log's delivery mode. */
    public const string DELIVERY_MODE = 'audit-log.delivery.mode';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Sso\Operations\OperationsSchedule  $operations
     */
    public function __construct(

        /** The configuration audit-log's delivery mode is read from when the schedule is built. */
        private Repository $config,

        /** SSO's own operations schedule, which registers nothing while SSO is not in use. */
        private OperationsSchedule $operations,
    ) {}

    /**
     * Register the members' scheduled work on the application's schedule.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function register(Schedule $schedule): void
    {
        $schedule->command(self::MFA_PRUNE)->daily();
        $schedule->command(self::AUTHORIZATION_PRUNE)->daily();

        $this->operations->register($schedule);

        if (!$this->drainsTheOutbox()) {
            return;
        }

        $schedule->command(self::AUDIT_DRAIN)->everyMinute();
    }

    /**
     * Whether audit-log's queued delivery through its outbox is on, read as
     * audit-log reads it: exactly `outbox`.
     *
     * @return bool
     */
    private function drainsTheOutbox(): bool
    {
        return $this->config->get(self::DELIVERY_MODE) === DeliveryMode::OUTBOX->value;
    }
}
