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
 * @method static \SineMacula\Laravel\Iam\Sso\SignInRedemption signIns()
 * @method static \SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption reauthentications()
 * @method static \SineMacula\Laravel\Iam\Sso\LinkRedemption links()
 * @method static \SineMacula\Laravel\Iam\Sso\CallerScope callers()
 * @method static \SineMacula\Laravel\Iam\Tenancy\TenantPolicyChanges tenantPolicies()
 * @method static \SineMacula\Laravel\Iam\Tenancy\TreeChanges treeChanges()
 * @method static \SineMacula\Laravel\Iam\Tenancy\ScopeWidenings scopeWidenings()
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
