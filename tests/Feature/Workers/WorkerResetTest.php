<?php

declare(strict_types = 1);

namespace Tests\Feature\Workers;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Sessions\KeptSessions;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Workers\WorkerReset;
use Tests\TestCase;

/**
 * Feature tests for the worker reset against the members' real scoped bindings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WorkerReset::class)]
final class WorkerResetTest extends TestCase
{
    /**
     * The reset forgets every scoped instance the application binds.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetForgetsEveryScopedInstance(): void
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        /** @var array<array-key, \Closure|string> $scoped */
        $scoped    = \Closure::bind(static fn (Container $container): array => $container->scopedInstances, null, Container::class)($app);
        $abstracts = array_values(array_filter($scoped, is_string(...)));

        self::assertContains(KeptSessions::class, $abstracts);

        $before = array_map($app->make(...), $abstracts);

        Iam::resetWorkerState();

        foreach ($abstracts as $index => $abstract) {
            self::assertNotSame($before[$index], $app->make($abstract), $abstract . ' was kept.');
        }
    }
}
