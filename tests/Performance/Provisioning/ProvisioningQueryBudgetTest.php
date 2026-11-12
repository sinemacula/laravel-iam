<?php

declare(strict_types = 1);

namespace Tests\Performance\Provisioning;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Iam\Provisioning\ProvisionOnUnlinkedResult;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Provisioning\ProvisionsPeople;
use Tests\Performance\PerformanceContractTestCase;

/**
 * Query budget for provisioning an unlinked `sign_in`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProvisionOnUnlinkedResult::class)]
final class ProvisioningQueryBudgetTest extends PerformanceContractTestCase
{
    use MigratesSso, RunsSsoFlows, SignsInPeople;

    /**
     * Arrange SSO.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();
    }

    /**
     * A provisioned sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProvisionedSignIn(): void
    {
        // Reads: the widening's two link reads, the helper's three locked reads
        // and its link storage's three. Writes: person, guard, membership, link
        // and links version. Five transactions, each committed.
        $this->underBudget(static function (self $test, \Closure $provision): void {
            $test->assertQueryBudget(8, 5, $provision, begins: 5, commits: 5);
        }, new ProvisionsPeople);

        $this->handoff();
    }

    /**
     * With no provisioner a dispatch reads and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoProvisioner(): void
    {
        $this->underBudget(static function (self $test, \Closure $provision): void {
            $test->assertQueryBudget(0, 0, $provision);
        });

        try {
            $this->handoff();

            self::fail('An unprovisioned sign-in was handed off.');
        } catch (AssertionFailedError $exception) {
            self::assertStringContainsString('unlinked', $exception->getMessage());
        }
    }

    /**
     * Register a second listener that binds the provisioner and runs it.
     *
     * @param  \Closure(self, \Closure(): void): void  $budget
     * @param  ?\SineMacula\Laravel\Iam\Contracts\Provisioner  $provisioner
     * @return void
     */
    private function underBudget(\Closure $budget, ?Provisioner $provisioner = null): void
    {
        Event::listen(ResultUnlinked::class, function (ResultUnlinked $event) use ($budget, $provisioner): void {

            $app = $this->app ?? self::fail('The application has not booted.');

            if ($provisioner !== null) {
                $app->instance(Provisioner::class, $provisioner);
            }

            $listener = $app->make(ProvisionOnUnlinkedResult::class);

            $budget($this, static function () use ($listener, $event): void {
                $listener->handle($event);
            });
        });
    }
}
