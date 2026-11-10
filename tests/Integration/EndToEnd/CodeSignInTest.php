<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;
use SineMacula\Laravel\Iam\Delivery\DeliverySettings;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;
use SineMacula\Laravel\Iam\Delivery\OneTimeCodeSenderAdapter;
use Tests\Concerns\DeliversThroughGateways;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * End-to-end tests of `laravel-authentication`'s one-time code sign-in
 * (IAM-3.13), by email address and by phone number, with both of the
 * application's gateways named and every adapter of this package's bound.
 *
 * A code asked for under an identifier type reaches the gateway
 * `iam.delivery.types` routes that type to, once, as this package's one
 * `CodeMessage`, the same message an MFA factor's code arrives as, and signs
 * the person in. `laravel-authentication` delivers from its own queued job once
 * the code has committed, so a gateway that throws fails the job and leaves the
 * code issued, never rolled back, and the queue's retry delivers that same
 * code. Everything runs on MySQL and PostgreSQL at READ COMMITTED and
 * REPEATABLE READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OneTimeCodeSenderAdapter::class)]
#[CoversClass(DeliverySettings::class)]
#[CoversClass(CodeMessage::class)]
final class CodeSignInTest extends TestCase
{
    use DeliversThroughGateways, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The person's phone number, in its normal form. */
    private const string PHONE = '+447700900789';

    /** @var string The person's email address, in its normal form. */
    private const string ADDRESS = 'ada.sign-in@example.test';

    /**
     * Queue the deliveries.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->queueDeliveries();
    }

    /**
     * Rows of `[isolation level, method, identifier type, identifier as given,
     * identifier in its normal form, channel]` for each code sign-in method at
     * each level.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: string, 4: string, 5: \SineMacula\Laravel\Iam\Delivery\Enums\Channel}>
     */
    public static function provideCodeSignIns(): iterable
    {
        foreach (self::provideIsolationLevels() as $name => [$level]) {
            yield $name . ', email' => [$level, 'email_code', 'email', 'Ada.Sign-In@Example.test', self::ADDRESS, Channel::EMAIL];

            yield $name . ', phone' => [$level, 'phone_code', 'phone', self::PHONE, self::PHONE, Channel::SMS];
        }
    }

    /**
     * A sign-in code asked for under an identifier type reaches the gateway the
     * type routes to once its delivery job runs, as this package's message from
     * `laravel-authentication` for a sign-in, to the identifier in its normal
     * form, for the person on the guard, naming no factor; nothing reaches the
     * other gateway, and the code signs the person in.
     *
     * @param  string  $level
     * @param  string  $method
     * @param  string  $type
     * @param  string  $given
     * @param  string  $destination
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCodeSignIns')]
    public function testACodeSignInIsDeliveredThroughTheGatewayItsTypeRoutesTo(
        string $level,
        string $method,
        string $type,
        string $given,
        string $destination,
        Channel $channel,
    ): void {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->person();
        $gateway = $this->gatewayOf($channel);
        $request = $this->codes()->send($method, [$type => $given], self::client());

        self::assertTrue($request->isSent(), $request->status->value);
        self::assertSame([], $gateway->sent(), 'The code is delivered once it has committed, by the queued job.');
        self::assertSame(1, $this->runDeliveries());
        self::assertCount(1, $gateway->sent());

        $message = $gateway->sent()[0];

        self::assertSame(Source::AUTHENTICATION, $message->source);
        self::assertSame(CodePurpose::SIGN_IN, $message->memberPurpose);
        self::assertSame(Purpose::SIGN_IN, $message->purpose);
        self::assertSame($channel, $message->channel);
        self::assertSame($type, $message->type);
        self::assertSame($destination, $message->destination());
        self::assertSame(self::GUARD, $message->application);
        self::assertIsThePerson($person, $message->recipient());
        self::assertNull($message->factor);
        self::assertTrue($message->expiresAt->isFuture());
        self::assertSame([], $this->otherGatewayThan($channel)->sent());

        $result = $this->signInWith($method, $type, $given, (string) $request->challengeId, $message->code->reveal());

        self::assertTrue($result->isSignedIn(), (string) $result->reason?->value);
        self::assertNotNull($result->session);
        self::assertTrue($person->sessions()->whereKey($result->session->record->getKey())->exists(), 'The session is the person\'s.');
    }

    /**
     * A gateway that throws fails the sign-in code's delivery job with its
     * exception, once the code has committed: the code stays issued, unused,
     * nothing is delivered, and the queue's retry of the job delivers that same
     * code, which then signs the person in.
     *
     * @param  string  $level
     * @param  string  $method
     * @param  string  $type
     * @param  string  $given
     * @param  string  $destination
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCodeSignIns')]
    public function testAFailedDeliveryLeavesTheCodeIssuedForTheQueuesRetry(
        string $level,
        string $method,
        string $type,
        string $given,
        string $destination,
        Channel $channel,
    ): void {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $this->person();

        $failure = new \RuntimeException('The provider refused the message.');
        $gateway = $this->gatewayOf($channel)->failNext($failure);
        $request = $this->codes()->send($method, [$type => $given], self::client());

        self::assertTrue($request->isSent(), 'laravel-authentication answers the request before the code is delivered.');
        self::assertSame($failure, $this->assertDeliveryFails(\RuntimeException::class));
        self::assertSame([], $gateway->sent());
        self::assertSame(1, DB::table('one_time_codes')->whereNull('consumed_at')->count(), 'The code stays issued.');

        $this->retryLastDelivery();

        $code = $gateway->lastCodeTo($destination, Purpose::SIGN_IN) ?? self::fail('The retry delivered nothing.');

        self::assertTrue($this->signInWith($method, $type, $given, (string) $request->challengeId, $code)->isSignedIn());
    }

    /**
     * Allow both code sign-in methods on the guard, beside the password.
     *
     * @return list<string>
     */
    #[\Override]
    protected function signInMethods(): array
    {
        return ['password', 'email_code', 'phone_code'];
    }

    /**
     * Name both gateways before any provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $this->nameTheGateways($app);
    }

    /**
     * A person whose email address and phone number are both verified, so
     * either signs them in by code.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    private function person(): Person
    {
        $person = $this->createPerson(self::ADDRESS);

        $person->forceFill([
            'phone'             => self::PHONE,
            'email_verified_at' => CarbonImmutable::now(),
            'phone_verified_at' => CarbonImmutable::now(),
        ])->save();

        return $person;
    }

    /**
     * Sign in with the code sent for the challenge.
     *
     * @param  string  $method
     * @param  string  $type
     * @param  string  $identifier
     * @param  string  $challenge
     * @param  string  $code
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInWith(string $method, string $type, string $identifier, string $challenge, #[\SensitiveParameter] string $code): SignInResult
    {
        return $this->sessions()->signIn($method, [$type => $identifier, 'challenge' => $challenge, 'code' => $code], new SignInContext(self::client()));
    }

    /**
     * `laravel-authentication`'s code service for the guard.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\CodeService
     */
    private function codes(): CodeService
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        return $auth->codes(self::GUARD);
    }
}
