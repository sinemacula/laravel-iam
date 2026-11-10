<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Exceptions;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Proofs\Channel as ProofChannel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as ProofPurpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;
use SineMacula\Laravel\Iam\Delivery\DeliverySettings;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;
use SineMacula\Laravel\Iam\Delivery\OneTimeCodeSenderAdapter;
use SineMacula\Laravel\Iam\Exceptions\DeliveryNotConfiguredException;
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;
use SineMacula\Laravel\Iam\Testing\FakeSmsGateway;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Delivery\AdmitsEveryFactorCode;
use Tests\Fixtures\Delivery\ScriptedGateway;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authentication`'s codes delivered through the
 * application's gateways (IAM-3.13), its one-time code sender pointed at them
 * by this package.
 *
 * A password reset code reaches the gateway its identifier type routes to, and
 * a further factor's code, whose type is its factor's channel, the gateway of
 * that channel, each as this package's one message, and the reset code resets
 * the password. `laravel-authentication` delivers from its own queued job,
 * pushed once the code commits (on a `sync` connection, once the response is
 * sent), so the gateway runs outside any transaction: a gateway that throws, or
 * a code that routes to no gateway, fails the job, and the code it issued
 * stays, unlike MFA's own, which roll back. They run on MySQL and PostgreSQL at
 * READ COMMITTED and REPEATABLE READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OneTimeCodeSenderAdapter::class)]
#[CoversClass(DeliverySettings::class)]
final class AuthenticationCodeDeliveryTest extends TestCase
{
    use MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The number the person's phone and SMS factor have. */
    private const string PHONE = '+447700900123';

    /** @var string The password a reset sets. */
    private const string NEW_PASSWORD = 'a different and longer passphrase';

    /**
     * `laravel-authentication`'s one-time code sender is this package's
     * adapter, pointed at the gateways the application names.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheOneTimeCodeSenderIsPointedAtTheGateways(): void
    {
        self::assertInstanceOf(OneTimeCodeSenderAdapter::class, $this->app?->make(OneTimeCodeSender::class));
    }

    /**
     * Rows of `[isolation level, identifier type, channel]` for a password
     * reset code to each of the person's identifiers.
     *
     * @return iterable<string, array{0: string, 1: string, 2: \SineMacula\Laravel\Iam\Delivery\Enums\Channel}>
     */
    public static function provideResetCodes(): iterable
    {
        foreach (self::provideIsolationLevels() as $name => [$level]) {
            yield $name . ', email' => [$level, 'email', Channel::EMAIL];

            yield $name . ', phone' => [$level, 'phone', Channel::SMS];
        }
    }

    /**
     * A password reset code reaches the gateway its identifier type routes to,
     * once its delivery job runs, as this package's message, and resets the
     * password.
     *
     * @param  string  $level
     * @param  string  $type
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideResetCodes')]
    public function testAResetCodeReachesTheGatewayItsTypeRoutesTo(string $level, string $type, Channel $channel): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$gateway, $other] = $this->fakes($channel);

        $person      = $this->person();
        $destination = $type === 'email' ? $person->email : self::PHONE;
        $request     = $this->auth()->passwords(self::GUARD)->sendResetCode($type, [$type => $destination], self::client());

        self::assertIsString($request->challengeId);
        self::assertSame([], $gateway->sent(), 'The code is delivered from the queued job, not the request.');

        $this->app?->terminate();

        self::assertSame([], $other->sent());
        self::assertCount(1, $gateway->sent());

        $message = $gateway->sent()[0];

        self::assertSame(self::GUARD, $message->application);
        self::assertSame(CodePurpose::PASSWORD_RESET, $message->memberPurpose);
        self::assertSame(Purpose::PASSWORD_RESET, $message->purpose);
        self::assertSame(Source::AUTHENTICATION, $message->source);
        self::assertSame($channel, $message->channel);
        self::assertSame($type, $message->type);
        self::assertSame($destination, $message->destination());
        self::assertIsThePerson($person, $message->recipient());
        self::assertNull($message->factor);

        $reset = $this->auth()->passwords(self::GUARD)->resetWithCode($type, [
            $type       => $destination,
            'challenge' => $request->challengeId,
            'code'      => $message->code->reveal(),
            'password'  => self::NEW_PASSWORD,
        ], self::client());

        self::assertTrue($reset->isReset());
    }

    /**
     * A further factor's code `laravel-authentication` issues on MFA's behalf
     * reaches the gateway of its factor's channel, which the identifier types
     * do not route, outside any transaction, as this package's message for an
     * additional factor, naming no factor.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAFactorCodeReachesTheGatewayOfItsChannel(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        /** @var \ArrayObject<string, mixed> $observed */
        $observed = new \ArrayObject;
        $gateway  = new ScriptedGateway(static function (CodeMessage $message, ScriptedGateway $gateway) use ($observed): void {
            $observed['message'] = $message;
            $observed['depth']   = DB::connection()->transactionLevel();

            $gateway->deliver($message);
        });

        $this->app?->instance(SmsGateway::class, $gateway);

        $email   = FakeEmailGateway::fake($this->app);
        $person  = $this->person();
        $request = $this->auth()->codes(self::GUARD)->sendFactorCode($this->factorBinding($person), self::client());

        self::assertIsString($request->challengeId);
        self::assertCount(0, $observed);

        $this->app?->terminate();

        $message = $observed['message'];

        self::assertInstanceOf(CodeMessage::class, $message);
        self::assertSame(0, $observed['depth'], 'laravel-authentication delivers once the code has committed.');
        self::assertSame(1, $gateway->deliveredTo(self::PHONE));
        self::assertSame([], $email->sent());
        self::assertSame(CodePurpose::MFA, $message->memberPurpose);
        self::assertSame(Purpose::ADDITIONAL_FACTOR, $message->purpose);
        self::assertSame(Source::AUTHENTICATION, $message->source);
        self::assertSame(Channel::SMS, $message->channel);
        self::assertSame('sms', $message->type);
        self::assertSame(self::PHONE, $message->destination());
        self::assertNull($message->factor);
    }

    /**
     * A gateway that throws fails `laravel-authentication`'s delivery job with
     * its exception, and the code the job was delivering stays, since it
     * committed before the job ran.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAGatewayThatThrowsFailsTheDeliveryJob(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$gateway] = $this->fakes(Channel::EMAIL);

        $failure = new \RuntimeException('The provider refused the message.');
        $person  = $this->person();

        $gateway->failNext($failure);

        $this->auth()->passwords(self::GUARD)->sendResetCode('email', ['email' => $person->email], self::client());

        $this->assertDeliveryJobFails($failure::class);

        self::assertSame([], $gateway->sent());
        self::assertSame(1, $this->codes());
    }

    /**
     * A code whose identifier type routes to no gateway fails the delivery job,
     * delivering nothing.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testACodeThatRoutesNowhereFailsTheDeliveryJob(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$sms, $email] = $this->fakes(Channel::SMS);

        config()->set('iam.delivery.types', ['email' => 'email']);

        $this->auth()->passwords(self::GUARD)->sendResetCode('phone', ['phone' => $this->person()->phone], self::client());

        $this->assertDeliveryJobFails(DeliveryNotConfiguredException::class);

        self::assertSame([], [...$sms->sent(), ...$email->sent()]);
        self::assertSame(1, $this->codes());
    }

    /**
     * Name a fake of each gateway before any provider registers, as a published
     * configuration file holds them, so `laravel-authentication`'s one-time
     * code sender is pointed at the gateways.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $app->make('config')->set('iam.delivery', [
            'email' => FakeEmailGateway::class,
            'sms'   => FakeSmsGateway::class,
            'types' => ['email' => 'email', 'phone' => 'sms'],
        ]);
    }

    /**
     * Deliver on a `sync` connection, so a code's delivery job runs once the
     * response is sent, and admit every factor code, so a further factor's code
     * can be sent without MFA's counters.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $app->make('config')->set('queue.default', 'sync');
        $app->bind(FactorCodeCounters::class, AdmitsEveryFactorCode::class);
    }

    /**
     * Send the response, so the delivery job runs, failing unless the job fails
     * with an exception of the class given.
     *
     * On the `sync` connection the job runs after the response. Laravel 13.41
     * and later report its exception there rather than rethrowing it, and
     * earlier releases rethrow it, so the failure is read from either.
     *
     * @param  class-string<\Throwable>  $class
     * @return void
     */
    private function assertDeliveryJobFails(string $class): void
    {
        $handler = Exceptions::fake();
        $thrown  = rescue(fn () => $this->app?->terminate(), static fn (\Throwable $exception): \Throwable => $exception, false);

        self::assertInstanceOf($class, $thrown ?? $handler->reported()[0] ?? null, 'The delivery job must fail.');
    }

    /**
     * Bind a fake of each gateway, and return the one of the channel, then the
     * other.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return list<\SineMacula\Laravel\Iam\Testing\FakeEmailGateway|\SineMacula\Laravel\Iam\Testing\FakeSmsGateway>
     */
    private function fakes(Channel $channel): array
    {
        $sms   = FakeSmsGateway::fake($this->app);
        $email = FakeEmailGateway::fake($this->app);

        return $channel === Channel::SMS ? [$sms, $email] : [$email, $sms];
    }

    /**
     * A person with a phone number as well as an address.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    private function person(): Person
    {
        $person = $this->createPerson();

        $person->update(['phone' => self::PHONE]);

        return $person;
    }

    /**
     * The binding of a step-up's code to the person's SMS factor, on a session
     * the person signs in to now.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     *
     * @throws \Throwable
     */
    private function factorBinding(Person $person): FactorCodeBinding
    {
        $session = $this->signIn($person)->record;

        return new FactorCodeBinding(
            new ProofBinding($person, self::GUARD, $session->getKey(), ProofPurpose::STEP_UP),
            'factor-sms',
            new ProofChannel(ChannelKind::SMS, self::PHONE),
        );
    }

    /**
     * How many codes `laravel-authentication` keeps.
     *
     * @return int
     */
    private function codes(): int
    {
        return DB::table('one_time_codes')->count();
    }

    /**
     * `laravel-authentication`'s manager.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function auth(): AuthManager
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        return $auth;
    }
}
