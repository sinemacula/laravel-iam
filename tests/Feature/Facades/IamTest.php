<?php

declare(strict_types = 1);

namespace Tests\Feature\Facades;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\IamManager;
use SineMacula\Laravel\Sso\Protocols\DriverScope;
use Tests\TestCase;

/**
 * Feature tests for the `Iam` facade: it stands for the `iam` manager and hands
 * each call to it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Iam::class)]
final class IamTest extends TestCase
{
    /**
     * The facade stands for the one `iam` manager.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheFacadeStandsForTheManager(): void
    {
        self::assertInstanceOf(IamManager::class, Iam::getFacadeRoot());
        self::assertSame($this->app?->make('iam'), Iam::getFacadeRoot());
    }

    /**
     * A cross-member transaction called through the facade runs the work in one
     * transaction and returns what it returns.
     *
     * @return void
     */
    public function testATransactionRunsThroughTheFacade(): void
    {
        self::assertSame(1, Iam::transaction(static fn (): int => DB::connection()->transactionLevel()));
    }

    /**
     * Resetting the worker state through the facade forgets the members' scoped
     * instances.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheWorkerStateResetsThroughTheFacade(): void
    {
        $before = $this->app?->make(DriverScope::class);

        Iam::resetWorkerState();

        self::assertNotSame($before, $this->app?->make(DriverScope::class));
    }
}
