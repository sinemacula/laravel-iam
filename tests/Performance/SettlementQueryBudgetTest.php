<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\MemberDefaults;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Storage\ConnectionAlignment;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Iam\Workers\WorkerReset;

/**
 * The statements this package makes as an application starts and as a worker
 * moves between requests and jobs: none, since aligning the storage
 * connections, checking them and applying the binding rule read configuration
 * and the container only, and so does the worker reset.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IamServiceProvider::class)]
#[CoversClass(ConnectionAlignment::class)]
#[CoversClass(StorageConnection::class)]
#[CoversClass(BindingRule::class)]
#[CoversClass(MemberDefaults::class)]
#[CoversClass(WorkerReset::class)]
final class SettlementQueryBudgetTest extends PerformanceContractTestCase
{
    /**
     * Registering and settling the package, as a late registration does at
     * once, makes no statement.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSettlingThePackageMakesNoStatement(): void
    {
        $this->app?->make('config')->set(StorageConnection::KEY, self::CONNECTION);

        $this->assertQueryBudget(0, 0, fn (): mixed => $this->app?->register(IamServiceProvider::class, true));
    }

    /**
     * Resetting the worker state makes no statement.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResettingTheWorkerStateMakesNoStatement(): void
    {
        $this->app?->make('auth')->guard();

        $this->assertQueryBudget(0, 0, fn (): mixed => $this->app?->make(WorkerReset::class)->reset());
    }
}
