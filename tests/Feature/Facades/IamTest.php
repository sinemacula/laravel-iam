<?php

declare(strict_types = 1);

namespace Tests\Feature\Facades;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\IamManager;
use SineMacula\Laravel\Iam\Sso\Callers;
use SineMacula\Laravel\Iam\Sso\LinkRedemption;
use SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption;
use SineMacula\Laravel\Iam\Sso\SignInRedemption;
use SineMacula\Laravel\Sso\Protocols\DriverScope;
use Tests\TestCase;

/**
 * Feature tests for the `Iam` facade.
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
     * A transaction through the facade runs the work and returns its result.
     *
     * @return void
     */
    public function testATransactionRunsThroughTheFacade(): void
    {
        self::assertSame(1, Iam::transaction(static fn (): int => DB::connection()->transactionLevel()));
    }

    /**
     * The facade answers each SSO redemption service and the callers service.
     *
     * @return void
     */
    public function testTheRedemptionsAreReachedThroughTheFacade(): void
    {
        self::assertInstanceOf(SignInRedemption::class, Iam::signIns());
        self::assertInstanceOf(ReauthenticationRedemption::class, Iam::reauthentications());
        self::assertInstanceOf(LinkRedemption::class, Iam::links());
        self::assertInstanceOf(Callers::class, Iam::callers());
    }

    /**
     * The facade annotates exactly the manager's public surface.
     *
     * @return void
     */
    public function testTheFacadeAnnotatesExactlyTheManagersSurface(): void
    {
        $manager = new \ReflectionClass(IamManager::class);
        $methods = [];

        foreach ($manager->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {

            if ($method->isConstructor()) {
                continue;
            }

            $methods[] = $method->getName();
        }

        preg_match_all('/@method\s+static\s+\S+\s+(\w+)\(/', (string) (new \ReflectionClass(Iam::class))->getDocComment(), $annotated);

        sort($methods);
        sort($annotated[1]);

        self::assertSame($methods, $annotated[1]);
    }

    /**
     * Resetting worker state through the facade forgets scoped instances.
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
