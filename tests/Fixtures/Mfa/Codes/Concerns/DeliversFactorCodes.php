<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\Codes\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Queue;
use SineMacula\Laravel\Authentication\Codes\SendOneTimeCode;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;

/**
 * Delivers the factor codes `laravel-authentication` sends for MFA's delivered
 * factors (IAM-3.9) to its fake one-time code sender, running each queued
 * `SendOneTimeCode` job as a queue worker would.
 *
 * A test calls `defineFactorCodes()` from `defineEnvironment()`, so the sender
 * is bound before MFA's boot check resolves its senders, and
 * `fakeFactorCodeDelivery()` once the application has booted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait DeliversFactorCodes
{
    /** @var ?\SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender The sender `laravel-authentication`'s deliveries reach. */
    private ?FakeOneTimeCodeSender $codeSender = null;

    /** @var int How many of the queued deliveries have been run. */
    private int $delivered = 0;

    /**
     * Offer `sms` and `email` as well as TOTP.
     *
     * @return list<string>
     */
    #[\Override]
    protected function mfaTypes(): array
    {
        return ['totp', 'sms', 'email'];
    }

    /**
     * Bind `laravel-authentication`'s fake one-time code sender as the
     * application's, before it boots.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    protected function defineFactorCodes(Application $app): void
    {
        $this->codeSender = FakeOneTimeCodeSender::fake($app);
    }

    /**
     * Queue `laravel-authentication`'s deliveries on a connection of their own
     * with no cooldown and the most deliveries a window allows, and fake the
     * queue.
     *
     * @return void
     */
    protected function fakeFactorCodeDelivery(): void
    {
        $config = $this->app?->make(ConfigRepository::class) ?? self::fail('The application has not booted.');

        $config->set('queue.default', 'deliveries');
        $config->set('queue.connections.deliveries', ['driver' => 'database']);
        $config->set('authentication.codes.resend_cooldown_seconds', 0);
        $config->set('authentication.codes.max_deliveries', 10);

        Queue::fake();

        $this->delivered = 0;
    }

    /**
     * Run every delivery queued since the last, as a queue worker would, and
     * return the messages they sent.
     *
     * @return list<\SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage>
     */
    protected function deliverFactorCodes(): array
    {
        $jobs = Queue::pushed(SendOneTimeCode::class)->values()->all();
        $from = count($this->codeSender()->sent());

        foreach (array_slice($jobs, $this->delivered) as $job) {

            self::assertInstanceOf(SendOneTimeCode::class, $job);

            $job->handle($this->app ?? self::fail('The application has not booted.'));
        }

        $this->delivered = count($jobs);

        return array_slice($this->codeSender()->sent(), $from);
    }

    /**
     * Run the deliveries queued since the last and return the code last sent to
     * the destination, failing the test when none was.
     *
     * @param  string  $destination
     * @return string
     */
    protected function deliveredCodeTo(string $destination): string
    {
        $this->deliverFactorCodes();

        return $this->codeSender()->lastCodeFor($destination) ?? self::fail('No code was delivered to the destination.');
    }

    /**
     * The deliveries queued and not yet run.
     *
     * @return int
     */
    protected function queuedDeliveries(): int
    {
        return Queue::pushed(SendOneTimeCode::class)->count() - $this->delivered;
    }

    /**
     * The fake one-time code sender `laravel-authentication`'s deliveries
     * reach.
     *
     * @return \SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender
     */
    protected function codeSender(): FakeOneTimeCodeSender
    {
        return $this->codeSender ?? self::fail('The delivery of factor codes has not been faked.');
    }
}
