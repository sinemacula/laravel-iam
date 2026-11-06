<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Assertions the gateway contracts share, whichever channel the gateway
 * delivers on: a message of every purpose is delivered once, a delivery logs
 * neither the code nor the destination, and a failure throws, delivers nothing
 * and names neither, its exception read, stack traces and all, as the worker's
 * exception handler reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GatewayAssert
{
    /** @var string The application this package's own fakes are proved for; a gateway of the application's is proved for the guard it serves. */
    public const string APPLICATION = 'contract';

    /** @var string Why a delivery that logs a context nested deeper than the kit reads fails. */
    private const string LOGGED_TOO_DEEP = 'A delivery must log no context nested deeper than the gateway kit reads, which could hide the code or the destination.';

    /** @var string Why a failed delivery whose exception holds a context nested too deep fails. */
    private const string THROWN_TOO_DEEP = 'A failed delivery\'s exception must hold nothing nested deeper than the gateway kit reads, which could hide the code or destination.';

    /**
     * A message on the channel for every purpose either member issues a code
     * for, for the application and to the recipient, each with a code and a
     * destination of its own: `laravel-authentication`'s, with its identifier
     * type (or, for a further factor's or an enrolment's code, its channel) and
     * no factor, then MFA's, with its factor's type and a masked summary of the
     * factor.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  string  $application
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $recipient
     * @return list<\SineMacula\Laravel\Iam\Delivery\CodeMessage>
     */
    public static function messages(Channel $channel, string $application, Authenticatable $recipient): array
    {
        $purposes  = [...array_filter(CodePurpose::cases(), static fn (CodePurpose $purpose): bool => $purpose !== CodePurpose::PASSWORD_RESET_LINK), ...MfaPurpose::cases()];
        $expiresAt = CarbonImmutable::now()->addMinutes(10)->startOfSecond();
        $messages  = [];

        foreach ($purposes as $index => $purpose) {
            $messages[] = new CodeMessage(
                $application,
                $purpose,
                $channel,
                self::type($channel, $purpose),
                self::destination($channel, $index),
                new Secret(sprintf('58%04d', 3170 + $index)),
                $expiresAt,
                $recipient,
                $purpose instanceof MfaPurpose ? new FactorSummary('contract-factor', $channel->value, 'Contract', '****', FactorStatus::CONFIRMED, false, null) : null,
            );
        }

        return $messages;
    }

    /**
     * Each message is delivered exactly once to its destination.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\EmailGateway|\SineMacula\Laravel\Iam\Contracts\SmsGateway  $gateway
     * @param  list<\SineMacula\Laravel\Iam\Delivery\CodeMessage>  $messages
     * @param  \Closure(string): int  $delivered
     * @return void
     */
    public static function assertDeliversOnce(EmailGateway|SmsGateway $gateway, array $messages, \Closure $delivered): void
    {
        foreach ($messages as $message) {

            $before = $delivered($message->destination());

            $gateway->send($message);

            Assert::assertSame($before + 1, $delivered($message->destination()), sprintf(
                'The %s gateway must deliver a %s code of %s\'s exactly once.',
                $message->channel->value,
                $message->memberPurpose->value,
                $message->source->value,
            ));
        }
    }

    /**
     * Delivering each message logs neither its code nor its destination.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\EmailGateway|\SineMacula\Laravel\Iam\Contracts\SmsGateway  $gateway
     * @param  list<\SineMacula\Laravel\Iam\Delivery\CodeMessage>  $messages
     * @return void
     *
     * @throws \Throwable
     */
    public static function assertLogsNothingOfTheMessage(EmailGateway|SmsGateway $gateway, array $messages): void
    {
        foreach ($messages as $message) {

            [$logged, $thrown] = LogRecorder::during(static fn () => $gateway->send($message));

            if ($thrown !== null) {
                throw $thrown;
            }

            self::assertReadsEverything($logged, self::LOGGED_TOO_DEEP);
            self::assertNamesNothingOf($logged, $message, 'A delivery must log neither the code nor the destination.');
        }
    }

    /**
     * Each delivery the provider fails throws, delivers nothing, and neither
     * its exception nor anything logged names the code or the destination.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\EmailGateway|\SineMacula\Laravel\Iam\Contracts\SmsGateway  $gateway
     * @param  list<\SineMacula\Laravel\Iam\Delivery\CodeMessage>  $messages
     * @param  \Closure(): void  $fail
     * @param  \Closure(string): int  $delivered
     * @return void
     */
    public static function assertEachFailureThrows(EmailGateway|SmsGateway $gateway, array $messages, \Closure $fail, \Closure $delivered): void
    {
        foreach ($messages as $message) {
            self::assertAFailureThrows($gateway, $message, $fail, $delivered);
        }
    }

    /**
     * A delivery the provider fails throws, delivers nothing, and neither its
     * exception nor anything logged names the code or the destination.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\EmailGateway|\SineMacula\Laravel\Iam\Contracts\SmsGateway  $gateway
     * @param  \SineMacula\Laravel\Iam\Delivery\CodeMessage  $message
     * @param  \Closure(): void  $fail
     * @param  \Closure(string): int  $delivered
     * @return void
     */
    private static function assertAFailureThrows(EmailGateway|SmsGateway $gateway, CodeMessage $message, \Closure $fail, \Closure $delivered): void
    {
        $before = $delivered($message->destination());

        $fail();

        [$logged, $thrown] = LogRecorder::during(static fn () => $gateway->send($message));

        Assert::assertInstanceOf(\Throwable::class, $thrown, 'A delivery that fails must throw, so the member keeps no code it reported sent.');
        Assert::assertSame($before, $delivered($message->destination()), 'A delivery that fails must deliver nothing.');

        // Read as the worker's exception handler reports it: the whole chain,
        // each with its stack trace and its frames' arguments
        $exception = [LogRecorder::exception($thrown)];

        self::assertReadsEverything($exception, self::THROWN_TOO_DEEP);
        self::assertNamesNothingOf($exception, $message, 'A failed delivery\'s exception must name neither the code nor the destination.');
        self::assertReadsEverything($logged, self::LOGGED_TOO_DEEP);
        self::assertNamesNothingOf($logged, $message, 'A failed delivery must log neither the code nor the destination.');
    }

    /**
     * The kit read every text in full: none holds a context nested deeper than
     * it reads, which could hide the code or the destination.
     *
     * @param  list<string>  $texts
     * @param  string  $failure
     * @return void
     */
    private static function assertReadsEverything(array $texts, string $failure): void
    {
        $unread = array_filter($texts, static fn (string $text): bool => str_contains($text, LogRecorder::UNREAD));

        Assert::assertSame([], $unread, $failure);
    }

    /**
     * None of the texts holds the message's code or destination.
     *
     * @param  list<string>  $texts
     * @param  \SineMacula\Laravel\Iam\Delivery\CodeMessage  $message
     * @param  string  $failure
     * @return void
     */
    private static function assertNamesNothingOf(array $texts, CodeMessage $message, string $failure): void
    {
        $code        = $message->code->reveal();
        $destination = $message->destination();
        $leaks       = array_filter($texts, static fn (string $text): bool => str_contains($text, $code) || str_contains($text, $destination));

        Assert::assertSame([], $leaks, $failure);
    }

    /**
     * The member's type of the destination: `laravel-authentication`'s
     * identifier type (`email`, `phone`) for its own codes, and the channel for
     * a factor's code of either member's.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose|\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return string
     */
    private static function type(Channel $channel, CodePurpose|MfaPurpose $purpose): string
    {
        $identifier = $purpose instanceof CodePurpose && $purpose !== CodePurpose::MFA && $purpose !== CodePurpose::ENROLLMENT;

        return $identifier && $channel === Channel::SMS ? 'phone' : $channel->value;
    }

    /**
     * The destination of the message at the index, in its normal form: an
     * address, or an E.164 number from the range set aside for drama.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  int  $index
     * @return string
     */
    private static function destination(Channel $channel, int $index): string
    {
        return $channel === Channel::EMAIL ? sprintf('contract-%d@example.test', $index) : sprintf('+4477009002%02d', $index);
    }
}
