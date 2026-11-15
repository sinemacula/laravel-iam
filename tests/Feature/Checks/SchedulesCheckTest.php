<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use Illuminate\Console\Scheduling\Schedule;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Checks\SchedulesCheck;
use SineMacula\Laravel\Iam\Scheduling\IamSchedule;
use Tests\Concerns\RunsChecks;
use Tests\TestCase;

/**
 * Feature tests for the schedule check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SchedulesCheck::class)]
final class SchedulesCheckTest extends TestCase
{
    use RunsChecks;

    /** @var string The note of runs left off the schedule. */
    private const string MISSING = 'Runs [%s] are not on the schedule; call `Iam::schedule($schedule)` from the application\'s `withSchedule()`.';

    /**
     * The prunes are noted, without failing, until something schedules them.
     *
     * @return void
     */
    public function testThePrunesAreNotedUntilThePackageSchedulesThem(): void
    {
        $checks = $this->check()->checks();

        self::assertSame([], self::problems($checks));
        self::assertSame([sprintf(self::MISSING, 'mfa:prune, authorization:prune')], self::notes($checks));
        self::assertTrue($this->check()->applies());
        self::assertSame('schedule', $this->check()->subject());

        $this->schedule()->command('mfa:prune --hours=1')->daily();
        $this->schedule()->call(static fn (): null => null)->daily();

        self::assertSame([sprintf(self::MISSING, 'authorization:prune')], self::notes($this->check()->checks()));

        $this->schedulePackage();

        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * The drain is noted while audit-log delivers through its outbox.
     *
     * @return void
     */
    public function testTheDrainIsNotedWhileTheOutboxIsOn(): void
    {
        $this->app?->make('config')->set(IamSchedule::DELIVERY_MODE, 'outbox');

        self::assertSame([sprintf(self::MISSING, 'mfa:prune, authorization:prune, audit-log:drain --until-empty')], self::notes($this->check()->checks()));

        $this->schedulePackage();

        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * SSO's runs are noted while SSO is in use.
     *
     * @return void
     */
    public function testSsoRunsAreNotedWhileSsoIsInUse(): void
    {
        $this->app?->make('config')->set('sso.features.oidc', true);

        $runs = 'mfa:prune, authorization:prune, sso:prune, sso:domains:recheck, sso:metadata:refresh, sso:keys:expiring';

        self::assertSame([sprintf(self::MISSING, $runs)], self::notes($this->check()->checks()));

        $this->schedulePackage();

        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * An SSO run with no cadence or a malformed one is not noted.
     *
     * @return void
     */
    public function testSsoRunsWithoutAValidCadenceAreNotNoted(): void
    {
        $config = $this->app?->make('config');

        $config?->set('sso.features.saml2', true);
        $config?->set('sso.operations.cadence.prune', null);
        $config?->set('sso.operations.cadence.domain_recheck', '');
        $config?->set('sso.operations.cadence.metadata_refresh', 'hourly');

        self::assertSame([sprintf(self::MISSING, 'mfa:prune, authorization:prune, sso:keys:expiring')], self::notes($this->check()->checks()));

        $this->schedulePackage();

        self::assertSame([], self::notes($this->check()->checks()));
    }

    /**
     * Register what `Iam::schedule()` registers on the application's schedule.
     *
     * @return void
     */
    private function schedulePackage(): void
    {
        $this->app?->make(IamSchedule::class)->register($this->schedule());
    }

    /**
     * The application's schedule.
     *
     * @return \Illuminate\Console\Scheduling\Schedule
     */
    private function schedule(): Schedule
    {
        $schedule = $this->app?->make(Schedule::class);

        assert($schedule instanceof Schedule);

        return $schedule;
    }

    /**
     * The check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\SchedulesCheck
     */
    private function check(): SchedulesCheck
    {
        $check = $this->app?->make(SchedulesCheck::class);

        assert($check instanceof SchedulesCheck);

        return $check;
    }
}
