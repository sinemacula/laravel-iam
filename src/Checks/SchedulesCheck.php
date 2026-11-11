<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Scheduling\IamSchedule;

/**
 * Notes each run `Iam::schedule()` registers that is not on the application's
 * schedule (IAM-2.6).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SchedulesCheck implements Check
{
    /** @var string The note of runs missing from the schedule. */
    private const string MISSING = 'Runs [%s] are not on the schedule; call `Iam::schedule($schedule)` from the application\'s `withSchedule()`.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container the application's schedule is resolved from. */
        private Container $container,

        /** The configuration audit-log's delivery mode is read from. */
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
     * A note naming the runs missing from the schedule.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [function (): ?string {

            $runs = [IamSchedule::MFA_PRUNE, IamSchedule::AUTHORIZATION_PRUNE];

            if ($this->config->get(IamSchedule::DELIVERY_MODE) === DeliveryMode::OUTBOX->value) {
                $runs[] = IamSchedule::AUDIT_DRAIN;
            }

            $scheduled = implode(PHP_EOL, array_map(static fn (Event $event): string => (string) $event->command, $this->container->make(Schedule::class)->events()));
            $missing   = array_filter($runs, static fn (string $run): bool => !str_contains($scheduled, $run));

            return $missing === [] ? null : sprintf(self::MISSING, implode(', ', $missing));
        }];
    }
}
