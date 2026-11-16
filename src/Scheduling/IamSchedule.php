<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Scheduling;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\Authorization\Console\PruneGrantsCommand;
use SineMacula\Laravel\Authorization\Console\UsageHeartbeatCommand;
use SineMacula\Laravel\Authorization\Console\UsagePruneCommand;
use SineMacula\Laravel\Mfa\Console\PruneCommand;
use SineMacula\Laravel\Sso\Operations\OperationsSchedule;

/**
 * Registers the members' scheduled work on the application's schedule.
 *
 * `mfa:prune`, `authorization:prune` and `authorization:usage-prune` run daily,
 * the usage heartbeat runs at least once an interval while usage tracking is
 * on, SSO's operations schedule is registered, and the audit-log drain runs
 * every minute while delivery is `outbox`. No task takes a cache mutex: each
 * command is safe to run on several servers at once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IamSchedule
{
    /** @var string MFA's pruning of unusable records. */
    public const string MFA_PRUNE = PruneCommand::NAME;

    /** @var string laravel-authorization's pruning of grants that no longer count. */
    public const string AUTHORIZATION_PRUNE = PruneGrantsCommand::NAME;

    /** @var string laravel-authorization's pruning of grant usage and coverage. */
    public const string USAGE_PRUNE = UsagePruneCommand::NAME;

    /** @var string laravel-authorization's extension of usage coverage to now. */
    public const string USAGE_HEARTBEAT = UsageHeartbeatCommand::NAME;

    /** @var string The key of laravel-authorization's usage tracking switch. */
    public const string USAGE_ENABLED = 'authorization.usage.enabled';

    /** @var string Audit-log's outbox delivery, until the outbox is empty. */
    public const string AUDIT_DRAIN = 'audit-log:drain --until-empty';

    /** @var string The key of audit-log's delivery mode. */
    public const string DELIVERY_MODE = 'audit-log.delivery.mode';

    /** @var string The key of laravel-authorization's usage interval, in seconds. */
    private const string USAGE_INTERVAL = 'authorization.usage.interval';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Sso\Operations\OperationsSchedule  $operations
     */
    public function __construct(

        /** Read when the schedule is built. */
        private Repository $config,

        /** SSO's operations schedule, which registers nothing while SSO is unused. */
        private OperationsSchedule $operations,
    ) {}

    /**
     * Register the members' scheduled work on the schedule.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     */
    public function register(Schedule $schedule): void
    {
        $schedule->command(self::MFA_PRUNE)->daily();
        $schedule->command(self::AUTHORIZATION_PRUNE)->daily();
        $schedule->command(self::USAGE_PRUNE)->daily();

        if ($this->config->get(self::USAGE_ENABLED) === true) {
            $schedule->command(self::USAGE_HEARTBEAT)->cron($this->heartbeatCadence());
        }

        $this->operations->register($schedule);

        if (!$this->drainsTheOutbox()) {
            return;
        }

        $schedule->command(self::AUDIT_DRAIN)->everyMinute();
    }

    /**
     * The heartbeat's cron: a step of the interval's whole minutes, or hourly.
     *
     * @return string
     */
    private function heartbeatCadence(): string
    {
        $interval = $this->config->get(self::USAGE_INTERVAL);

        if (!is_numeric($interval) || $interval >= 3600) {
            return '0 * * * *';
        }

        return '*/' . intdiv((int) $interval, 60) . ' * * * *';
    }

    /**
     * Whether audit-log's delivery mode is exactly `outbox`.
     *
     * @return bool
     */
    private function drainsTheOutbox(): bool
    {
        return $this->config->get(self::DELIVERY_MODE) === DeliveryMode::OUTBOX->value;
    }
}
