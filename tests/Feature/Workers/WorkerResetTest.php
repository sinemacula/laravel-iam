<?php

declare(strict_types = 1);

namespace Tests\Feature\Workers;

use Illuminate\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Database\RequiredWork;
use SineMacula\Laravel\Authentication\Sessions\KeptSessions;
use SineMacula\Laravel\Authentication\Sessions\WatchedSessions;
use SineMacula\Laravel\Iam\Audit\JobCallers;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Transactions\AfterConnectionCommits;
use SineMacula\Laravel\Iam\Workers\WorkerReset;
use Tests\TestCase;

/**
 * Feature tests for flushing every member's request state against the scoped
 * bindings the installed members actually make, so a scoped binding a member
 * adds is never left out of the reset.
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

    /** @var list<string> This package's frame state, the frames of the queued jobs running, which the reset keeps as it keeps audit-log's. */
    private const array FRAMES = [JobCallers::class];

    /** @var string The namespace of `laravel-audit-log`, whose scoped execution frames it enters and leaves itself, and which the reset keeps. */
    private const string AUDIT_LOG_NAMESPACE = 'SineMacula\Laravel\AuditLog\\';

    /**
     * The reset first runs the work a commit left held, a commit callback
     * having failed, before it forgets the record holding it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testResetRunsTheWorkACommitLeftHeldFirst(): void
    {
        /** @var \ArrayObject<int, true> $runs */
        $runs       = new \ArrayObject;
        $connection = DB::connection();

        self::assertInstanceOf(Connection::class, $connection);

        try {
            $connection->transaction(static function () use ($connection, $runs): void {

                (new AfterConnectionCommits)->run($connection, static function () use ($runs): void {
                    $runs->append(true);
                });

                $connection->afterCommit(static fn () => throw new \LogicException('A callback failed.'));
            });
        } catch (\LogicException) {
            // The commit finished with the work held.
        }

        self::assertCount(0, $runs);

        Iam::resetWorkerState();

        self::assertCount(1, $runs);
    }

    /**
     * The reset forgets every scoped instance the installed members and this
     * package bind for a unit of work's request state, as the members bind
     * them, so the next unit of work builds its own: `laravel-authentication`'s
     * `KeptSessions`, `RequiredWork` and `WatchedSessions` among them.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetForgetsEveryScopedInstanceTheMembersBind(): void
    {
        $abstracts = array_values(array_filter($this->scopedAbstracts(), self::isRequestState(...)));

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
     * The reset keeps every other scoped instance: `laravel-audit-log`'s, which
     * it enters and leaves itself as each unit of work starts and ends, this
     * package's frames of the queued jobs running, which it keeps as it keeps
     * audit-log's, and Laravel's own.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetKeepsEveryOtherScopedInstance(): void
    {
        $abstracts = array_values(array_filter($this->scopedAbstracts(), static fn (string $abstract): bool => !self::isRequestState($abstract)));

        self::assertNotEmpty(array_filter($abstracts, static fn (string $abstract): bool => str_starts_with($abstract, self::AUDIT_LOG_NAMESPACE)));
        self::assertContains(JobCallers::class, $abstracts);

        $before = array_map(fn (string $abstract): mixed => $this->app?->make($abstract), $abstracts);

        Iam::resetWorkerState();

        foreach ($abstracts as $index => $abstract) {
            self::assertSame($before[$index], $this->app?->make($abstract), $abstract . ' was forgotten.');
        }
    }

    /**
     * The reset points `laravel-authentication`'s auth manager at the
     * application being reset before it resets the guards, so the guards are
     * reset to that application's request, not to one the manager held before.
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
     * Whether the scoped abstract holds request state the reset forgets: one an
     * installed member, other than `laravel-audit-log`, or this package binds,
     * but for this package's frame state.
     *
     * @param  string  $abstract
     * @return bool
     */
    private static function isRequestState(string $abstract): bool
    {
        return self::isMembers($abstract) && !in_array($abstract, self::FRAMES, true);
    }

    /**
     * Whether the scoped abstract is one an installed member, other than
     * `laravel-audit-log`, or this package binds: a class of its namespace, or
     * a key under its name.
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
     * Return the string abstracts the application keeps as scoped, read from
     * the property Laravel's own `forgetScopedInstances()` reads.
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
