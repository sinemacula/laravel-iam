<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * IAM facade.
 *
 * Static interface to the `IamManager` singleton. It annotates exactly the
 * manager's surface; any method the manager does not declare is refused.
 *
 * @formatter:off
 *
 * @phpcs:disable Generic.Files.LineLength.TooLong
 *
 * @method static mixed transaction(\Closure(): mixed $work, ?int $attempts = null)
 * @method static void resetWorkerState()
 *
 * @phpcs:enable Generic.Files.LineLength.TooLong
 *
 * @formatter:on
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @see         \SineMacula\Laravel\Iam\IamManager
 */
final class Iam extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    #[\Override]
    protected static function getFacadeAccessor(): string
    {
        return 'iam';
    }
}
