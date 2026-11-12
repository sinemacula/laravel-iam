<?php

declare(strict_types = 1);

namespace Tests\Feature\Workers;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Database\RequiredWork;
use SineMacula\Laravel\Authentication\Sessions\KeptSessions;
use SineMacula\Laravel\Authentication\Sessions\WatchedSessions;
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
    /** @var list<string> The namespaces of the members whose scoped instances hold request state the reset forgets, and this package's own. */
    private const array MEMBER_NAMESPACES = [
        'SineMacula\Laravel\Authentication\\',
        'SineMacula\Laravel\Authorization\\',
        'SineMacula\Laravel\Mfa\\',
        'SineMacula\Laravel\Sso\\',
        'SineMacula\Laravel\Iam\\',
    ];

    /** @var list<string> The first segment of the string keys those members, and this package, bind under. */
    private const array MEMBER_KEYS = ['authentication', 'authorization', 'mfa', 'sso', 'iam'];

    /** @var string The namespace of `laravel-audit-log`, whose scoped execution frames it enters and leaves itself, and which the reset keeps. */
    private const string AUDIT_LOG_NAMESPACE = 'SineMacula\Laravel\AuditLog\\';

    /**
     * The reset forgets every scoped instance the members and package bind.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetForgetsEveryScopedInstanceTheMembersBind(): void
    {
        $abstracts = array_values(array_filter($this->scopedAbstracts(), self::isMembers(...)));

        self::assertContains(KeptSessions::class, $abstracts);
        self::assertContains(RequiredWork::class, $abstracts);
        self::assertContains(WatchedSessions::class, $abstracts);

        $before = array_map(fn (string $abstract): mixed => $this->app?->make($abstract), $abstracts);

        Iam::resetWorkerState();

        foreach ($abstracts as $index => $abstract) {
            self::assertNotSame($before[$index], $this->app?->make($abstract), $abstract . ' was kept.');
        }
    }

    /**
     * The reset keeps audit-log's and Laravel's scoped instances.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetKeepsEveryOtherScopedInstance(): void
    {
        $abstracts = array_values(array_filter($this->scopedAbstracts(), static fn (string $abstract): bool => !self::isMembers($abstract)));

        self::assertNotEmpty(array_filter($abstracts, static fn (string $abstract): bool => str_starts_with($abstract, self::AUDIT_LOG_NAMESPACE)));

        $before = array_map(fn (string $abstract): mixed => $this->app?->make($abstract), $abstracts);

        Iam::resetWorkerState();

        foreach ($abstracts as $index => $abstract) {
            self::assertSame($before[$index], $this->app?->make($abstract), $abstract . ' was forgotten.');
        }
    }

    /**
     * The reset points the auth manager at the application being reset.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetPointsTheAuthManagerAtTheApplicationBeingReset(): void
    {
        $app  = $this->app ?? self::fail('The application has not booted.');
        $auth = \Mockery::mock(AuthManager::class);

        $auth->shouldReceive('setApplication')->once()->with($app)->ordered()->andReturnSelf();
        $auth->shouldReceive('forgetGuardState')->once()->ordered();

        $app->instance('auth', $auth);

        (new WorkerReset($app))->reset();
    }

    /**
     * Whether a member other than audit-log, or this package, binds it.
     *
     * @param  string  $abstract
     * @return bool
     */
    private static function isMembers(string $abstract): bool
    {
        foreach (self::MEMBER_NAMESPACES as $namespace) {

            if (str_starts_with($abstract, $namespace)) {
                return true;
            }
        }

        return in_array(preg_split('/[.:]/', $abstract, 2)[0] ?? '', self::MEMBER_KEYS, true);
    }

    /**
     * The scoped abstracts, as `forgetScopedInstances()` reads them.
     *
     * @return list<string>
     */
    private function scopedAbstracts(): array
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        /** @var array<array-key, \Closure|string> $scoped */
        $scoped = \Closure::bind(static fn (Container $container): array => $container->scopedInstances, null, Container::class)($app);

        return array_values(array_filter($scoped, is_string(...)));
    }
}
