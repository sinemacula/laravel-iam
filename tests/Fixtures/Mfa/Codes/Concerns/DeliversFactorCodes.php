<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\Codes\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Queue;
use SineMacula\Laravel\Authentication\Codes\SendOneTimeCode;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;
use SineMacula\Laravel\Iam\Testing\FakeSmsGateway;

/**
 * Delivers the factor codes `laravel-authentication` sends for MFA's delivered
 * factors (IAM-3.9), as a queue worker would: the queue is faked, and each
 * `SendOneTimeCode` job queued since the last delivery is run against
 * `laravel-authentication`'s fake one-time code sender, so a test reads the
 * code a person would receive.
 *
 * Before any provider registers, the MFA application offers `sms` and `email`,
 * and the application names a fake of each of this package's gateways, so the
 * binding rule points `laravel-authentication`'s one-time code sender and MFA's
 * senders at them, and MFA's challenge gateway at `laravel-authentication`'s
 * factor codes; once the providers have registered, a fake of each is bound as
 * the application's, so a test can read what reached it. Once it has booted,
 * `laravel-authentication`'s fake one-time code sender replaces this package's,
 * so a delivered code is read from it, and nothing reaches the gateways, which
 * only MFA's own senders would call, so a test can show MFA's senders deliver
 * nothing. Deliveries are queued on a connection of their own, never run
 * inline, with no cooldown and the most deliveries a window allows, so a test
 * may send a code as often as it needs to; the settings are set one by one
 * then, after every member has merged its own, which they would otherwise
 * replace.
 *
 * Used with `MigratesMembers`, `SignsInPeople` and `ArrangesDeliveredFactors`;
 * a test calls `defineFactorCodes()` from `defineEnvironment()`, which runs
 * once every provider has registered, and `fakeFactorCodeDelivery()` once the
 * application has booted.
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

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeSmsGateway The application's SMS gateway, which MFA's SMS sender is pointed at. */
    private ?FakeSmsGateway $smsGateway = null;

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeEmailGateway The application's email gateway, which MFA's email sender is pointed at. */
    private ?FakeEmailGateway $emailGateway = null;

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
     * Load the application's configuration, then name a fake of each gateway,
     * before any provider registers, as a published configuration file holds
     * them.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        assert($app instanceof Application);

        $app->make(ConfigRepository::class)->set('iam.delivery', [
            'email' => FakeEmailGateway::class,
            'sms'   => FakeSmsGateway::class,
            'types' => ['email' => 'email', 'phone' => 'sms'],
        ]);
    }

    /**
     * Bind a fake of each gateway as the application's, before it boots.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    protected function defineFactorCodes(Application $app): void
    {
        $this->smsGateway   = FakeSmsGateway::fake($app);
        $this->emailGateway = FakeEmailGateway::fake($app);
    }

    /**
     * Queue `laravel-authentication`'s deliveries on a connection of their own
     * with no cooldown and the most deliveries a window allows, and fake the
     * queue and its one-time code sender.
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

        $this->codeSender = FakeOneTimeCodeSender::fake($this->app);
        $this->delivered  = 0;
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

    /**
     * The application's gateways, which only MFA's own senders would reach once
     * `laravel-authentication`'s fake one-time code sender is bound.
     *
     * @return list<\SineMacula\Laravel\Iam\Testing\FakeEmailGateway|\SineMacula\Laravel\Iam\Testing\FakeSmsGateway>
     */
    protected function gateways(): array
    {
        return [
            $this->smsGateway   ?? self::fail('The gateways have not been bound.'),
            $this->emailGateway ?? self::fail('The gateways have not been bound.'),
        ];
    }
}
