<?php

declare(strict_types = 1);

namespace Tests\Feature\Provisioning;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Provisioning\ProvisionOnUnlinkedResult;
use SineMacula\Laravel\Iam\Testing\FakeProvisioner;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\RunsInOctaneSandboxes;
use Tests\Fixtures\Sso\PlainIdentity;
use Tests\TestCase;

/**
 * Feature tests for the registration of the listener that provisions SSO's
 * unlinked results (IAM-7.1): it is registered on SSO's event whatever any
 * switch says, does nothing at all while no provisioner is bound, asks the
 * provisioner bound when the event is dispatched, never one kept since, and
 * resolves the listener and its collaborators from the application current at
 * the dispatch, so under Octane the request's sandbox's provisioner is the one
 * asked, through the worker's events dispatcher.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IamServiceProvider::class)]
#[CoversClass(ProvisionOnUnlinkedResult::class)]
final class ProvisioningListenerTest extends TestCase
{
    use RunsInOctaneSandboxes;

    /**
     * The listener is registered on SSO's unlinked result.
     *
     * @return void
     */
    public function testTheListenerIsRegisteredOnSsosEvent(): void
    {
        self::assertTrue(Event::hasListeners(ResultUnlinked::class));
    }

    /**
     * With no provisioner bound, a dispatch does nothing: no transaction is
     * opened and nothing is read or written.
     *
     * @return void
     */
    public function testWithNoProvisionerTheListenerDoesNothing(): void
    {
        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        Event::dispatch(self::unlinked());

        self::assertSame(0, $queries);
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * A provisioner bound once the application has booted is the one asked at
     * the next dispatch.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAProvisionerBoundOnceBootedIsAsked(): void
    {
        $asked = new \RuntimeException('Asked.');

        FakeProvisioner::fake(static fn (): Identity => throw $asked);

        self::assertSame($asked, self::thrownBy(static fn (): mixed => Event::dispatch(self::unlinked())));
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * An identity that is no Eloquent model is refused as one the provisioner
     * did not create, whatever it says of itself, before anything else is
     * asked.
     *
     * @return void
     */
    public function testAnIdentityThatIsNoModelIsRefused(): void
    {
        $fake = FakeProvisioner::fake(static fn (): Identity => new PlainIdentity(['id' => 1, 'exists' => true, 'wasRecentlyCreated' => true]));

        $thrown = self::thrownBy(static fn (): mixed => Event::dispatch(self::unlinked()));

        self::assertInstanceOf(\LogicException::class, $thrown);
        self::assertStringContainsString(sprintf('an identity of [%s] it did not create', PlainIdentity::class), $thrown->getMessage());
        self::assertSame([], $fake->memberships());
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * Under Octane, the provisioner the request's sandbox binds is the one
     * asked, through the events dispatcher the worker resolved before the
     * sandbox was made, never the worker's own.
     *
     * @return void
     */
    public function testTheSandboxsProvisionerIsAsked(): void
    {
        $this->app?->make('events');

        $worker = FakeProvisioner::fake(static fn (): Identity => self::fail('The worker\'s provisioner was asked.'));

        $this->inOctaneSandbox(static function (Application $sandbox): void {

            $asked = new \RuntimeException('The sandbox\'s provisioner was asked.');

            FakeProvisioner::fake(static fn (): Identity => throw $asked, null, $sandbox);

            self::assertSame($asked, self::thrownBy(static fn (): mixed => Event::dispatch(self::unlinked())));
        });

        self::assertSame([], $worker->identities());
    }

    /**
     * An unlinked `sign_in` result's event, with a grant issued for it.
     *
     * @return \SineMacula\Laravel\Sso\Events\ResultUnlinked
     */
    private static function unlinked(): ResultUnlinked
    {
        $result = new VerifiedResult(
            'https://idp.example.test',
            'subject-1',
            null,
            'connection-1',
            'tenant-1',
            'oidc',
            self::GUARD,
            Purpose::SIGN_IN,
            RequestReference::fromString('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
            [],
            false,
            new AuthenticationContext(CarbonImmutable::now()->startOfSecond()),
        );

        return new ResultUnlinked(new EventContext(CarbonImmutable::now()), $result, ProvisioningGrant::issue($result, 'request-1', CarbonImmutable::now()->addMinute()));
    }

    /**
     * What the closure throws, failing the test unless it throws.
     *
     * @param  \Closure(): mixed  $call
     * @return \Throwable
     */
    private static function thrownBy(\Closure $call): \Throwable
    {
        try {
            $call();
        } catch (\Throwable $exception) {
            return $exception;
        }

        self::fail('Nothing was thrown.');
    }
}
