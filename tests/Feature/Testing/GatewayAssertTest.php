<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Carbon\CarbonImmutable;
use GuzzleHttp\Psr7\Response as Psr7Response;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;
use SineMacula\Laravel\Iam\Testing\FakeSmsGateway;
use SineMacula\Laravel\Iam\Testing\Seams\EmailGatewayContract;
use SineMacula\Laravel\Iam\Testing\Seams\GatewayAssert;
use SineMacula\Laravel\Iam\Testing\Seams\GatewayContract;
use SineMacula\Laravel\Iam\Testing\Seams\LogRecorder;
use SineMacula\Laravel\Iam\Testing\Seams\SmsGatewayContract;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use Tests\Fixtures\Delivery\RefusingProvider;
use Tests\Fixtures\Delivery\ScriptedGateway;
use Tests\Fixtures\Testing\LoggedJson;
use Tests\Fixtures\Testing\LoggedJsonException;
use Tests\Fixtures\Testing\LoggedProperties;
use Tests\Fixtures\Testing\LoggedString;
use Tests\TestCase;

/**
 * Proves this package's gateway contracts catch what they promise to
 * (IAM-3.13): a well-behaved gateway of either channel passes every one, and a
 * gateway that delivers twice, logs the code or the destination however deeply
 * and inside whatever object or exception the log would write, its stack trace
 * included, logs a context deeper than the kit reads, swallows a failure,
 * delivers before it fails, or names the code or the destination in its
 * failure, its trace included, fails the contract that forbids it, and a kit
 * that cannot read the log, with events faked, fails rather than passes. The
 * kit's messages cover every purpose of both members, each with its own code
 * and destination.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EmailGatewayContract::class)]
#[CoversClass(SmsGatewayContract::class)]
#[CoversClass(GatewayContract::class)]
#[CoversClass(GatewayAssert::class)]
#[CoversClass(LogRecorder::class)]
final class GatewayAssertTest extends TestCase
{
    /**
     * A well-behaved gateway of either channel passes every contract.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWellBehavedGatewayPassesEveryContract(): void
    {
        foreach ([Channel::EMAIL, Channel::SMS] as $channel) {

            $gateway = ScriptedGateway::wellBehaved();

            self::deliversOnce($channel, $gateway);
            self::logsNothing($channel, $gateway);
            self::failureThrows($channel, $gateway);
        }

        $this->addToAssertionCount(1);
    }

    /**
     * The kit's messages cover every purpose of both members on the channel,
     * each with a code and a destination of its own, in its normal form, and a
     * factor's summary for MFA's alone.
     *
     * @return void
     */
    public function testTheMessagesCoverEveryPurposeOfBothMembers(): void
    {
        CarbonImmutable::setTestNow('2026-11-05 12:00:00.250');

        $recipient = new GenericUser(['id' => 'contract-recipient']);
        $email     = GatewayAssert::messages(Channel::EMAIL, 'web', $recipient);
        $sms       = GatewayAssert::messages(Channel::SMS, 'web', $recipient);

        $purposes = [
            CodePurpose::SIGN_IN,
            CodePurpose::VERIFICATION,
            CodePurpose::MFA,
            CodePurpose::ENROLLMENT,
            CodePurpose::PASSWORD_RESET,
            CodePurpose::CHANGE_IDENTIFIER,
            ...MfaPurpose::cases(),
        ];

        self::assertSame($purposes, array_map(static fn (CodeMessage $message): CodePurpose|MfaPurpose => $message->memberPurpose, $sms));
        self::assertSame(array_fill(0, 10, 'email'), array_map(static fn (CodeMessage $message): string => $message->type, $email));
        $types = ['phone', 'phone', 'sms', 'sms', 'phone', 'phone', 'sms', 'sms', 'sms', 'sms'];

        self::assertSame($types, array_map(static fn (CodeMessage $message): string => $message->type, $sms));
        self::assertSame('contract-0@example.test', $email[0]->destination());
        self::assertSame('+447700900209', $sms[9]->destination());
        $codes = ['583170', '583171', '583172', '583173', '583174', '583175', '583176', '583177', '583178', '583179'];

        self::assertSame($codes, array_map(static fn (CodeMessage $message): string => $message->code->reveal(), $sms));
        self::assertCount(10, array_unique(array_map(static fn (CodeMessage $message): string => $message->destination(), $email)));

        foreach ([...$email, ...$sms] as $message) {

            $factor = new FactorSummary('contract-factor', $message->channel->value, 'Contract', '****', FactorStatus::CONFIRMED, false, null);

            self::assertSame('web', $message->application);
            self::assertSame($recipient, $message->recipient());
            self::assertEquals($message->source === Source::MFA ? $factor : null, $message->factor);
            self::assertEquals(CarbonImmutable::parse('2026-11-05 12:10:00'), $message->expiresAt);
        }
    }

    /**
     * Rows of `[channel]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Iam\Delivery\Enums\Channel}>
     */
    public static function provideChannels(): iterable
    {
        yield 'email' => [Channel::EMAIL];

        yield 'sms' => [Channel::SMS];
    }

    /**
     * A gateway that delivers a message twice fails the delivery contract.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return void
     */
    #[DataProvider('provideChannels')]
    public function testAGatewayThatDeliversTwiceFails(Channel $channel): void
    {
        $gateway = new ScriptedGateway(static function (CodeMessage $message, ScriptedGateway $gateway): void {
            $gateway->deliver($message);
            $gateway->deliver($message);
        });

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('gateway must deliver a sign_in code of authentication\'s exactly once');

        self::deliversOnce($channel, $gateway);
    }

    /**
     * Rows of `[contract, check, the channel it checks]`.
     *
     * @return iterable<string, array{0: class-string<\SineMacula\Laravel\Iam\Testing\Seams\GatewayContract>, 1: string, 2: \SineMacula\Laravel\Iam\Delivery\Enums\Channel}>
     */
    public static function provideContractChecks(): iterable
    {
        foreach ([EmailGatewayContract::class => Channel::EMAIL, SmsGatewayContract::class => Channel::SMS] as $contract => $channel) {
            foreach (['delivery', 'logging', 'failure'] as $check) {
                yield sprintf('%s %s', $channel->value, $check) => [$contract, $check, $channel];
            }
        }
    }

    /**
     * A channel's contract checks only that channel's gateways: a gateway of
     * the other channel fails each of its checks before any message is sent.
     *
     * @param  class-string<\SineMacula\Laravel\Iam\Testing\Seams\GatewayContract>  $contract
     * @param  string  $check
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideContractChecks')]
    public function testAGatewayOfTheOtherChannelFailsTheContract(string $contract, string $check, Channel $channel): void
    {
        $gateway   = $channel === Channel::EMAIL ? new FakeSmsGateway : new FakeEmailGateway;
        $delivered = static fn (string $destination): int => count($gateway->sentTo($destination));

        try {
            match ($check) {
                'delivery' => $contract::assertDeliversEveryPurposeOnce($gateway, GatewayAssert::APPLICATION, self::recipient(), $delivered),
                'logging'  => $contract::assertLogsNothingOfTheMessage($gateway, GatewayAssert::APPLICATION, self::recipient()),
                default    => $contract::assertAFailureThrows($gateway, GatewayAssert::APPLICATION, self::recipient(), static function () use ($gateway): void {
                    $gateway->failNext();
                }, $delivered),
            };
        } catch (AssertionFailedError $failure) {
            self::assertStringStartsWith(sprintf('The %s contract checks %s gateways only.', $channel->value, $channel->value), $failure->getMessage());
            self::assertSame([], $gateway->sent());

            return;
        }

        self::fail('A gateway of the other channel must fail the contract.');
    }

    /**
     * A gateway that delivers nothing for one of the purposes fails the
     * delivery contract.
     *
     * @return void
     */
    public function testAGatewayThatSkipsAPurposeFails(): void
    {
        $gateway = new ScriptedGateway(static function (CodeMessage $message, ScriptedGateway $gateway): void {
            if ($message->memberPurpose === MfaPurpose::STEP_UP) {
                return;
            }

            $gateway->deliver($message);
        });

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The sms gateway must deliver a step_up code of mfa\'s exactly once.');

        self::deliversOnce(Channel::SMS, $gateway);
    }

    /**
     * Rows of `[what the gateway logs]`, each naming the code or the
     * destination somewhere.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Iam\Delivery\CodeMessage): void}>
     */
    public static function provideLeaks(): iterable
    {
        yield 'the code in the message' => [static fn (CodeMessage $message) => Log::info('Sent ' . $message->code->reveal())];

        yield 'the destination in the context' => [static fn (CodeMessage $message) => Log::info('Sent', ['to' => $message->destination()])];

        yield 'the code deep in the context' => [static fn (CodeMessage $message) => Log::info('Sent', ['request' => ['body' => ['text' => $message->code->reveal()]]])];

        yield 'the destination nine levels deep' => [static fn (CodeMessage $message) => Log::info('Deep', [
            'a' => ['b' => ['c' => ['d' => ['e' => ['f' => ['g' => ['h' => $message->destination()]]]]]]],
        ])];

        yield 'the code in a provider\'s response' => [static fn (CodeMessage $message) => Log::info('Accepted', [
            'response' => new Response(new Psr7Response(201, [], (string) json_encode([
                'to'   => $message->destination(),
                'body' => 'Your code is ' . $message->code->reveal(),
            ]))),
        ])];

        yield 'the code in a string' => [static fn (CodeMessage $message) => Log::info('Sent', ['body' => new LoggedString('Your code is ' . $message->code->reveal())])];

        yield 'the destination in a JSON form' => [static fn (CodeMessage $message) => Log::info('Sent', ['request' => new LoggedJson(['to' => $message->destination()])])];

        yield 'the destination in a public property' => [static fn (CodeMessage $message) => Log::info('Sent', [
            'request' => new LoggedProperties(['to' => $message->destination()]),
        ])];

        yield 'the destination in an exception\'s previous one' => [static function (CodeMessage $message): void {
            $previous = new \RuntimeException('No route to ' . $message->destination());

            Log::warning('Retried', ['exception' => new \RuntimeException('Retried', 0, $previous)]);
        }];

        yield 'the destination in a logged exception\'s trace arguments' => [static function (CodeMessage $message): void {
            try {
                RefusingProvider::send($message->destination(), 'Your code is ready');
            } catch (\RuntimeException $exception) {
                Log::warning('The provider failed.', ['exception' => $exception]);
            }
        }];

        yield 'the code in a logged exception\'s previous trace' => [static function (CodeMessage $message): void {
            try {
                RefusingProvider::send('Code ' . $message->code->reveal());
            } catch (\RuntimeException $exception) {
                Log::warning('Retried', ['exception' => new \RuntimeException('Retried', 0, $exception)]);
            }
        }];

        yield 'the code as a logged exception\'s code' => [static fn (CodeMessage $message) => Log::warning('Refused', [
            'exception' => new \RuntimeException('Refused', (int) $message->code->reveal()),
        ])];

        yield 'the destination in a logged exception\'s JSON form' => [static fn (CodeMessage $message) => Log::warning('Refused', [
            'exception' => new LoggedJsonException('Refused', ['to' => $message->destination()]),
        ])];
    }

    /**
     * A gateway that logs the code or the destination fails the logging
     * contract, however deeply it is logged.
     *
     * @param  \Closure(\SineMacula\Laravel\Iam\Delivery\CodeMessage): void  $leak
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideLeaks')]
    public function testAGatewayThatLogsTheMessageFails(\Closure $leak): void
    {
        $gateway = new ScriptedGateway(static function (CodeMessage $message, ScriptedGateway $gateway) use ($leak): void {
            $leak($message);
            $gateway->deliver($message);
        });

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A delivery must log neither the code nor the destination.');

        self::logsNothing(Channel::EMAIL, $gateway);
    }

    /**
     * A gateway that logs, but nothing of the message the log would write (a
     * private property is never written), passes the logging contract.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGatewayThatLogsNothingOfTheMessagePasses(): void
    {
        $gateway = new ScriptedGateway(static function (CodeMessage $message, ScriptedGateway $gateway): void {
            Log::info('Sent a code', ['purpose' => $message->purpose, 'attempt' => 1, 'sent' => true, 'at' => $message->expiresAt, 'factor' => $message->factor]);
            Log::info('Accepted', ['response' => new LoggedProperties(['status' => 201, 'hidden' => new LoggedProperties('elsewhere', $message->destination())])]);
            $gateway->deliver($message);
        });

        self::logsNothing(Channel::SMS, $gateway);

        $this->addToAssertionCount(1);
    }

    /**
     * A gateway that logs a context nested deeper than the kit reads fails the
     * logging contract, whatever lies at the bottom, since it could be the
     * code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGatewayThatLogsTooDeepFails(): void
    {
        $gateway = new ScriptedGateway(static function (CodeMessage $message, ScriptedGateway $gateway): void {
            Log::info('Deep', self::deepContext());
            $gateway->deliver($message);
        });

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A delivery must log no context nested deeper than the gateway kit reads');

        self::logsNothing(Channel::SMS, $gateway);
    }

    /**
     * A failed delivery that logs a context nested deeper than the kit reads
     * fails the failure contract.
     *
     * @return void
     */
    public function testAFailedDeliveryThatLogsTooDeepFails(): void
    {
        $gateway = new ScriptedGateway(static function (CodeMessage $message, ScriptedGateway $gateway): void {
            if (!$gateway->failing) {
                $gateway->deliver($message);

                return;
            }

            Log::error('Refused', self::deepContext());

            throw new \RuntimeException('Refused');
        });

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A delivery must log no context nested deeper than the gateway kit reads');

        self::failureThrows(Channel::EMAIL, $gateway);
    }

    /**
     * Rows of `[contract check]` that read the log.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideLoggingChecks(): iterable
    {
        yield 'logging' => ['logging'];

        yield 'failure' => ['failure'];
    }

    /**
     * With events faked, the log's entries never reach the kit, so a gateway
     * that logs every code fails each check that reads the log, rather than
     * pass it unseen.
     *
     * @param  string  $check
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideLoggingChecks')]
    public function testTheLoggingChecksFailWhileEventsAreFaked(string $check): void
    {
        Event::fake();
        Log::forgetChannel('null');

        $gateway = new ScriptedGateway(static function (CodeMessage $message, ScriptedGateway $gateway): void {
            Log::info('Sent ' . $message->code->reveal() . ' to ' . $message->destination());

            if ($gateway->failing) {
                throw new \RuntimeException('Refused');
            }

            $gateway->deliver($message);
        });

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage(LogRecorder::UNREADABLE);

        $check === 'logging' ? self::logsNothing(Channel::EMAIL, $gateway) : self::failureThrows(Channel::EMAIL, $gateway);
    }

    /**
     * A gateway that throws while delivering a message fails the logging
     * contract with its own exception.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGatewayThatThrowsWhileDeliveringFailsTheLoggingContract(): void
    {
        $failure = new \LogicException('The gateway is broken.');
        $gateway = new ScriptedGateway(static fn () => throw $failure);

        try {
            self::logsNothing(Channel::EMAIL, $gateway);
        } catch (\LogicException $exception) {
            self::assertSame($failure, $exception);

            return;
        }

        self::fail('A gateway that throws must fail the logging contract.');
    }

    /**
     * Rows of `[what the gateway does when the provider fails, the failure
     * the contract reports]`.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Iam\Delivery\CodeMessage, \Tests\Fixtures\Delivery\ScriptedGateway): void, 1: string}>
     */
    public static function provideBadFailures(): iterable
    {
        yield 'it swallows the failure' => [static fn () => null, 'A delivery that fails must throw'];

        yield 'it delivers, then throws' => [static function (CodeMessage $message, ScriptedGateway $gateway): void {
            $gateway->deliver($message);

            throw new \RuntimeException('The receipt was lost.');
        }, 'A delivery that fails must deliver nothing.'];

        yield 'its exception names the code' => [static function (CodeMessage $message): void {
            throw new \RuntimeException('Refused ' . $message->code->reveal());
        }, 'A failed delivery\'s exception must name neither'];

        yield 'its previous exception names the destination' => [static function (CodeMessage $message): void {
            throw new \RuntimeException('Refused', 0, new \RuntimeException('Unknown ' . $message->destination()));
        }, 'A failed delivery\'s exception must name neither'];

        yield 'it logs the destination' => [static function (CodeMessage $message): void {
            Log::error('Could not reach ' . $message->destination());

            throw new \RuntimeException('Refused');
        }, 'A failed delivery must log neither'];

        yield 'its trace names the code' => [static function (CodeMessage $message): void {
            RefusingProvider::send('Code ' . $message->code->reveal());
        }, 'A failed delivery\'s exception must name neither'];

        yield 'its previous exception\'s trace names the destination' => [static function (CodeMessage $message): void {
            try {
                RefusingProvider::send($message->destination());
            } catch (\RuntimeException $exception) {
                throw new \RuntimeException('Refused', 0, $exception);
            }
        }, 'A failed delivery\'s exception must name neither'];

        yield 'its exception\'s JSON form names the code' => [static function (CodeMessage $message): void {
            throw new LoggedJsonException('Refused', ['body' => 'Code ' . $message->code->reveal()]);
        }, 'A failed delivery\'s exception must name neither'];

        yield 'its exception\'s JSON form is nested too deep' => [static function (): void {
            throw new LoggedJsonException('Refused', self::deepContext());
        }, 'A failed delivery\'s exception must hold nothing nested deeper than the gateway kit reads'];
    }

    /**
     * A gateway that handles a provider's failure badly fails the failure
     * contract.
     *
     * @param  \Closure(\SineMacula\Laravel\Iam\Delivery\CodeMessage, \Tests\Fixtures\Delivery\ScriptedGateway): void  $failing
     * @param  string  $reported
     * @return void
     */
    #[DataProvider('provideBadFailures')]
    public function testAGatewayThatFailsBadlyFails(\Closure $failing, string $reported): void
    {
        $gateway = new ScriptedGateway(static function (CodeMessage $message, ScriptedGateway $gateway) use ($failing): void {
            if ($gateway->failing) {
                $failing($message, $gateway);

                return;
            }

            $gateway->deliver($message);
        });

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage($reported);

        self::failureThrows(Channel::SMS, $gateway);
    }

    /**
     * Send the log nowhere: what the gateways log is read from its event.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $app->make('config')->set('logging.default', 'null');
    }

    /**
     * Run the channel's delivery contract against the gateway.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  \Tests\Fixtures\Delivery\ScriptedGateway  $gateway
     * @return void
     */
    private static function deliversOnce(Channel $channel, ScriptedGateway $gateway): void
    {
        $delivered = $gateway->deliveredTo(...);

        match ($channel) {
            Channel::EMAIL => EmailGatewayContract::assertDeliversEveryPurposeOnce($gateway, GatewayAssert::APPLICATION, self::recipient(), $delivered),
            Channel::SMS   => SmsGatewayContract::assertDeliversEveryPurposeOnce($gateway, GatewayAssert::APPLICATION, self::recipient(), $delivered),
        };
    }

    /**
     * Run the channel's logging contract against the gateway.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  \Tests\Fixtures\Delivery\ScriptedGateway  $gateway
     * @return void
     *
     * @throws \Throwable
     */
    private static function logsNothing(Channel $channel, ScriptedGateway $gateway): void
    {
        match ($channel) {
            Channel::EMAIL => EmailGatewayContract::assertLogsNothingOfTheMessage($gateway, GatewayAssert::APPLICATION, self::recipient()),
            Channel::SMS   => SmsGatewayContract::assertLogsNothingOfTheMessage($gateway, GatewayAssert::APPLICATION, self::recipient()),
        };
    }

    /**
     * Run the channel's failure contract against the gateway.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  \Tests\Fixtures\Delivery\ScriptedGateway  $gateway
     * @return void
     */
    private static function failureThrows(Channel $channel, ScriptedGateway $gateway): void
    {
        $fail = static function () use ($gateway): void {
            $gateway->failing = true;
        };
        $delivered = $gateway->deliveredTo(...);

        match ($channel) {
            Channel::EMAIL => EmailGatewayContract::assertAFailureThrows($gateway, GatewayAssert::APPLICATION, self::recipient(), $fail, $delivered),
            Channel::SMS   => SmsGatewayContract::assertAFailureThrows($gateway, GatewayAssert::APPLICATION, self::recipient(), $fail, $delivered),
        };

        $gateway->failing = false;
    }

    /**
     * A context nested one level deeper than the kit reads, holding nothing of
     * any message.
     *
     * @return array<array-key, mixed>
     */
    private static function deepContext(): array
    {
        $deep = ['nothing'];

        for ($level = 1; $level < 16; $level++) {
            $deep = [$deep];
        }

        return $deep;
    }

    /**
     * The identity every message is for.
     *
     * @return \Illuminate\Auth\GenericUser
     */
    private static function recipient(): GenericUser
    {
        return new GenericUser(['id' => 'contract-recipient']);
    }
}
