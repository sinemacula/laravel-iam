<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Scheduling;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\Authorization\Console\PruneGrantsCommand;
use SineMacula\Laravel\Mfa\Console\PruneCommand;
use SineMacula\Laravel\Sso\Operations\OperationsSchedule;

/**
 * Registers the members' scheduled work on the application's schedule.
 *
 * `mfa:prune` and `authorization:prune` run daily, SSO's operations schedule is
 * registered, and the audit-log drain runs every minute while delivery is
 * `outbox`. No task takes a cache mutex: each command is safe to run on several
 * servers at once.
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

    /** @var string Audit-log's outbox delivery, until the outbox is empty. */
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

        $this->operations->register($schedule);

        if (!$this->drainsTheOutbox()) {
            return;
        }

        $schedule->command(self::AUDIT_DRAIN)->everyMinute();
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
