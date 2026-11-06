<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Queue;
use SineMacula\Laravel\Authentication\Codes\SendOneTimeCode;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;
use SineMacula\Laravel\Iam\Testing\FakeSmsGateway;

/**
 * Delivers every member's codes through the application's gateways, a fake of
 * each, as an application that names both runs: `laravel-authentication`'s
 * one-time code sender and MFA's senders are pointed at them by the binding
 * rule, and `laravel-authentication`'s queued delivery jobs are held on a faked
 * queue until the test runs them, as a worker would once the code has
 * committed, and runs a failed one again, as the queue's retry would.
 *
 * Name the gateways from `resolveApplicationConfiguration()`, before any
 * provider registers, as a published configuration file holds them, and queue
 * the deliveries once the application has booted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait DeliversThroughGateways
{
    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeEmailGateway The application's email gateway. */
    private ?FakeEmailGateway $emailGateway = null;

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeSmsGateway The application's SMS gateway. */
    private ?FakeSmsGateway $smsGateway = null;

    /** @var int How many of the queued delivery jobs the test has run. */
    private int $ranDeliveries = 0;

    /**
     * Name a fake of each gateway, and the shipped routes of each identifier
     * type, in the application's configuration.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    protected function nameTheGateways(Application $app): void
    {
        $app->make(ConfigRepository::class)->set('iam.delivery', [
            'email' => FakeEmailGateway::class,
            'sms'   => FakeSmsGateway::class,
            'types' => ['email' => 'email', 'phone' => 'sms'],
        ]);
    }

    /**
     * Bind a fake of each gateway, hold `laravel-authentication`'s delivery
     * jobs on a faked queue of a connection that is not synchronous, and let a
     * code go to the same destination again at once, up to ten times.
     *
     * @return void
     */
    protected function queueDeliveries(): void
    {
        $app    = $this->app ?? self::fail('The application has not booted.');
        $config = $app->make(ConfigRepository::class);

        $config->set('queue.default', 'deliveries');
        $config->set('queue.connections.deliveries', ['driver' => 'database']);
        $config->set('authentication.codes.resend_cooldown_seconds', 0);
        $config->set('authentication.codes.max_deliveries', 10);

        Queue::fake();

        $this->emailGateway  = FakeEmailGateway::fake($app);
        $this->smsGateway    = FakeSmsGateway::fake($app);
        $this->ranDeliveries = 0;
    }

    /**
     * Run every delivery job queued since the last run, in order, as a worker
     * would, and return how many ran. A job that throws is counted as run, and
     * its exception is rethrown.
     *
     * @return int
     *
     * @throws \Throwable
     */
    protected function runDeliveries(): int
    {
        $jobs = $this->deliveryJobs();
        $from = $this->ranDeliveries;

        foreach (array_slice($jobs, $from) as $job) {

            $this->ranDeliveries++;

            $job->handle($this->app ?? self::fail('The application has not booted.'));
        }

        return count($jobs) - $from;
    }

    /**
     * Run the last delivery job that ran once more, as the queue's retry of a
     * failed job would.
     *
     * @return void
     */
    protected function retryLastDelivery(): void
    {
        $job = $this->deliveryJobs()[$this->ranDeliveries - 1] ?? self::fail('No delivery job has run.');

        $job->handle($this->app ?? self::fail('The application has not booted.'));
    }

    /**
     * Run the delivery jobs queued since the last run, failing unless one fails
     * with an exception of the class given, and return it.
     *
     * @param  class-string<\Throwable>  $class
     * @return \Throwable
     */
    protected function assertDeliveryFails(string $class): \Throwable
    {
        try {
            $this->runDeliveries();
        } catch (\Throwable $exception) {

            self::assertInstanceOf($class, $exception);

            return $exception;
        }

        self::fail('The delivery did not fail.');
    }

    /**
     * The application's gateway of the channel.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return \SineMacula\Laravel\Iam\Testing\FakeEmailGateway|\SineMacula\Laravel\Iam\Testing\FakeSmsGateway
     */
    protected function gatewayOf(Channel $channel): FakeEmailGateway|FakeSmsGateway
    {
        return match ($channel) {
            Channel::EMAIL => $this->emailGateway ?? self::fail('The deliveries have not been queued.'),
            Channel::SMS   => $this->smsGateway   ?? self::fail('The deliveries have not been queued.'),
        };
    }

    /**
     * The application's gateway of the other channel.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return \SineMacula\Laravel\Iam\Testing\FakeEmailGateway|\SineMacula\Laravel\Iam\Testing\FakeSmsGateway
     */
    protected function otherGatewayThan(Channel $channel): FakeEmailGateway|FakeSmsGateway
    {
        return $this->gatewayOf($channel === Channel::EMAIL ? Channel::SMS : Channel::EMAIL);
    }

    /**
     * Every delivery job `laravel-authentication` has queued, in order.
     *
     * @return list<\SineMacula\Laravel\Authentication\Codes\SendOneTimeCode>
     */
    private function deliveryJobs(): array
    {
        $jobs = [];

        foreach (Queue::pushed(SendOneTimeCode::class) as $job) {

            self::assertInstanceOf(SendOneTimeCode::class, $job);

            $jobs[] = $job;
        }

        return $jobs;
    }
}
