<?php

declare(strict_types = 1);

namespace Tests\Feature\Sso;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Iam\Sso\RenewalRecorder;
use SineMacula\Laravel\Iam\Transactions\CommittedWork;
use Tests\TestCase;

/**
 * Feature tests for the records SSO's redemptions keep for one request: each is
 * one instance for the whole of a request or a job, resolved through this
 * package's own key for scoped adapters, and the worker reset forgets it, so
 * the next unit of work starts with none (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IamServiceProvider::class)]
final class RedemptionRecordsTest extends TestCase
{
    /**
     * Rows of each record.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideRecords(): iterable
    {
        yield 'the admitted redemption' => [AdmittedRedemptions::class];

        yield 'the renewal recorder' => [RenewalRecorder::class];

        yield 'the committed work' => [CommittedWork::class];
    }

    /**
     * The record is one instance for the whole unit of work, the one held under
     * the package's key for scoped adapters.
     *
     * @param  class-string  $record
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideRecords')]
    public function testTheRecordIsOneInstanceForTheUnitOfWork(string $record): void
    {
        $app      = $this->app ?? self::fail('The application has not booted.');
        $instance = $app->make($record);

        self::assertInstanceOf($record, $instance);
        self::assertSame($instance, $app->make($record));
        self::assertSame($instance, $app->make(BindingRule::SCOPED_PREFIX . $record));
    }

    /**
     * The worker reset forgets the record, so the next unit of work is given a
     * new one.
     *
     * @param  class-string  $record
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideRecords')]
    public function testTheWorkerResetForgetsTheRecord(string $record): void
    {
        $app    = $this->app ?? self::fail('The application has not booted.');
        $before = $app->make($record);

        Iam::resetWorkerState();

        self::assertNotSame($before, $app->make($record));
    }
}
