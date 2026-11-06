<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Auth\GenericUser;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;
use SineMacula\Laravel\Iam\Testing\Concerns\RecordsGatewayMessages;
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;
use SineMacula\Laravel\Iam\Testing\FakeSmsGateway;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use Tests\TestCase;

/**
 * Feature tests for this package's fake gateways (IAM-3.13): `fake()` binds a
 * fresh fake as the application's gateway, which keeps every message it is
 * given for a test to read, by destination and purpose, and fails the next
 * delivery, once, when told to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeEmailGateway::class)]
#[CoversClass(FakeSmsGateway::class)]
#[CoversTrait(RecordsGatewayMessages::class)]
final class RecordsGatewayMessagesTest extends TestCase
{
    /** @var string The address the messages go to. */
    private const string ADDRESS = 'ada@example.test';

    /** @var string Another address. */
    private const string OTHER = 'grace@example.test';

    /**
     * Rows of `[fake class, contract]`.
     *
     * @return iterable<string, array{0: class-string<\SineMacula\Laravel\Iam\Testing\FakeEmailGateway|\SineMacula\Laravel\Iam\Testing\FakeSmsGateway>, 1: class-string}>
     */
    public static function provideFakes(): iterable
    {
        yield 'email' => [FakeEmailGateway::class, EmailGateway::class];

        yield 'sms' => [FakeSmsGateway::class, SmsGateway::class];
    }

    /**
     * `fake()` binds a fresh fake as the application's gateway, each call
     * replacing the last.
     *
     * @param  class-string<\SineMacula\Laravel\Iam\Testing\FakeEmailGateway|\SineMacula\Laravel\Iam\Testing\FakeSmsGateway>  $fake
     * @param  class-string  $contract
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideFakes')]
    public function testFakeBindsAFreshFakeAsTheApplicationsGateway(string $fake, string $contract): void
    {
        $first = $fake::fake();

        self::assertSame($first, $this->app?->make($contract));
        self::assertSame($contract, $fake::GATEWAY);

        $second = $fake::fake($this->app);

        self::assertNotSame($first, $second);
        self::assertSame($second, $this->app->make($contract));
    }

    /**
     * `fake()` binds the fake in the container given, leaving the application's
     * as it is.
     *
     * @param  class-string<\SineMacula\Laravel\Iam\Testing\FakeEmailGateway|\SineMacula\Laravel\Iam\Testing\FakeSmsGateway>  $fake
     * @param  class-string  $contract
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideFakes')]
    public function testFakeBindsInTheContainerGiven(string $fake, string $contract): void
    {
        $container = new Container;
        $bound     = $fake::fake($container);

        self::assertSame($bound, $container->make($contract));
        self::assertFalse($this->app?->bound($contract));
    }

    /**
     * The fake keeps every message, oldest first, and reads them back by
     * filter, by destination, and as the code last sent to a destination, for a
     * purpose or any.
     *
     * @return void
     */
    public function testTheFakeKeepsEveryMessage(): void
    {
        $fake   = new FakeEmailGateway;
        $first  = self::message(CodePurpose::SIGN_IN, self::ADDRESS, '111111');
        $second = self::message(MfaPurpose::STEP_UP, self::OTHER, '222222');
        $third  = self::message(CodePurpose::VERIFICATION, self::ADDRESS, '333333');

        $fake->send($first);
        $fake->send($second);
        $fake->send($third);

        self::assertSame([$first, $second, $third], $fake->sent());
        self::assertSame([$second], $fake->sent(static fn (CodeMessage $message): bool => $message->purpose === Purpose::ADDITIONAL_FACTOR));
        self::assertSame([$first, $third], $fake->sentTo(self::ADDRESS));
        self::assertSame('333333', $fake->lastCodeTo(self::ADDRESS));
        self::assertSame('111111', $fake->lastCodeTo(self::ADDRESS, Purpose::SIGN_IN));
        self::assertSame('222222', $fake->lastCodeTo(self::OTHER));
        self::assertNull($fake->lastCodeTo(self::OTHER, Purpose::SIGN_IN));
        self::assertNull($fake->lastCodeTo('nobody@example.test'));
    }

    /**
     * Told to fail, the fake throws in place of the next delivery, keeping
     * nothing, and keeps the delivery after it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFakeFailsTheNextDeliveryOnce(): void
    {
        $fake    = new FakeSmsGateway;
        $message = self::message(MfaPurpose::SIGN_IN, '+447700900123', '444444');

        self::assertSame($fake, $fake->failNext());

        try {
            $fake->send($message);
            self::fail('The fake must fail the next delivery.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The fake gateway was told to fail this delivery.', $exception->getMessage());
        }

        self::assertSame([], $fake->sent());

        $fake->send($message);

        self::assertSame([$message], $fake->sent());
    }

    /**
     * Told to fail with an exception of the test's, the fake throws that
     * exception.
     *
     * @return void
     */
    public function testTheFakeFailsWithTheExceptionGiven(): void
    {
        $fake    = new FakeEmailGateway;
        $failure = new \LogicException('The provider is down.');

        $fake->failNext($failure);

        $this->expectExceptionObject($failure);

        $fake->send(self::message(CodePurpose::PASSWORD_RESET, self::ADDRESS, '555555'));
    }

    /**
     * Reset, the fake forgets every message and any failure it was told to
     * throw.
     *
     * @return void
     */
    public function testResetForgetsMessagesAndFailures(): void
    {
        $fake    = new FakeEmailGateway;
        $message = self::message(CodePurpose::SIGN_IN, self::ADDRESS, '666666');

        $fake->send($message);
        $fake->failNext();
        $fake->reset();

        self::assertSame([], $fake->sent());

        $fake->send($message);

        self::assertSame([$message], $fake->sent());
    }

    /**
     * A message for the purpose, to the destination, with the code.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose|\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  string  $destination
     * @param  string  $code
     * @return \SineMacula\Laravel\Iam\Delivery\CodeMessage
     */
    private static function message(CodePurpose|MfaPurpose $purpose, string $destination, string $code): CodeMessage
    {
        $channel = str_contains($destination, '@') ? Channel::EMAIL : Channel::SMS;

        return new CodeMessage('api', $purpose, $channel, $channel->value, $destination, new Secret($code), CarbonImmutable::now()->addMinutes(10), new GenericUser(['id' => 1]));
    }
}
