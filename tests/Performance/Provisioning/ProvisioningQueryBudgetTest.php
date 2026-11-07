<?php

declare(strict_types = 1);

namespace Tests\Performance\Provisioning;

use Illuminate\Support\Facades\DB;
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
 * Query budget for provisioning an unlinked `sign_in` (IAM-7.1): every
 * statement the listener makes for one dispatch of SSO's unlinked result, from
 * the transaction it opens to its commit, so a read or a write added to
 * provisioning, by this package, by SSO's scope widening or by its provisioning
 * helper, is seen here.
 *
 * The listener under budget is a second one, registered after the package's,
 * which does nothing while no provisioner is configured: the provisioner is
 * bound only once the package's own has returned, and the second listener
 * handles the same dispatch, with the grant unspent. A provisioned sign-in
 * writes the application's identity and membership, takes the new identity's
 * guard and reads nothing of its links but the two reads SSO's scope widening
 * makes to find none, and the helper's checks and its one link: the listener
 * opens one transaction, and each of SSO's steps is a savepoint of it. With no
 * provisioner, nothing at all is read or written.
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
        // Reads (8): SSO's scope widening's two of the new identity's links by
        // a verified domain (a plain read, then the locking one), finding
        // none; the helper's three under its locks (the connection, the
        // request, the subject's link), then its link storage's three (the
        // connection, the identity's links in it for the limit, the subject's
        // active link). Writes (5): the application's person, the identity's
        // guard, the application's membership, the link, and the connection's
        // links version. Transactions: the listener's, the widening's
        // savepoint, the helper's, its link storage's and the link's insert,
        // each begun and committed. Settings: on PostgreSQL, MySQL and
        // MariaDB, the listener's transaction set to READ COMMITTED, as its
        // first statement or just before it begins; none on SQLite.
        $this->underBudget(static function (self $test, \Closure $provision): void {
            $test->assertQueryBudget(8, 5, $provision, begins: 5, commits: 5, settings: DB::connection()->getDriverName() === 'sqlite' ? 0 : 1);
        }, new ProvisionsPeople);

        $this->handoff();
    }

    /**
     * With no provisioner, a dispatch reads and writes nothing, and the flow
     * ends as SSO's `unlinked`.
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
     * Register a second listener of SSO's unlinked result that binds the
     * provisioner given, if any, and hands the budget the provisioning to run.
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
