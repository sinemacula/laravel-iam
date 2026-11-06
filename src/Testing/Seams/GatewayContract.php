<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams;

use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\DeliverySeams;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;

/**
 * What every gateway of one channel must guarantee, as assertions: a message of
 * every purpose either member issues a code for is delivered once, a delivery
 * logs neither the code nor the destination, and a delivery that fails throws,
 * delivers nothing, and names neither in its exception or the log.
 *
 * Each channel's contract, `EmailGatewayContract` or `SmsGatewayContract`,
 * names its channel, and refuses a gateway that is not that channel's. The
 * messages are for the application the test case names, the guard the gateway
 * serves, so a gateway that chooses its template, brand or sender by the
 * application, and refuses one it does not serve, is proved as it runs; they go
 * to destinations of the kit's own. What is logged is what Laravel's log is
 * given, read through its `MessageLogged` event as the log's formatters write
 * it: an object by its JSON form, its string or its public properties, and an
 * exception, with each previous one, by its type, code, message, file and its
 * stack trace, then its JSON form. The exception a failed delivery throws is
 * read the same way, as the worker's exception handler reports it. A stack
 * trace is read with every argument of every frame whole, whatever PHP is set
 * to record, so a gateway that passes the code or the destination to a call
 * whose exception it logs or throws fails, unless that parameter is marked
 * `#[\SensitiveParameter]`. A context nested deeper than the kit reads fails,
 * and so does a kit that cannot see the log at all, with events faked, rather
 * than pass without looking.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
abstract class GatewayContract
{
    /**
     * A message of every purpose, from either member, is delivered exactly once
     * to its destination.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\EmailGateway|\SineMacula\Laravel\Iam\Contracts\SmsGateway  $gateway
     * @param  string  $application
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $recipient
     * @param  \Closure(string): int  $delivered
     * @return void
     */
    public static function assertDeliversEveryPurposeOnce(EmailGateway|SmsGateway $gateway, string $application, Authenticatable $recipient, \Closure $delivered): void
    {
        GatewayAssert::assertDeliversOnce($gateway, self::messages($gateway, $application, $recipient), $delivered);
    }

    /**
     * Delivering a message logs neither its code nor its destination.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\EmailGateway|\SineMacula\Laravel\Iam\Contracts\SmsGateway  $gateway
     * @param  string  $application
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $recipient
     * @return void
     *
     * @throws \Throwable
     */
    public static function assertLogsNothingOfTheMessage(EmailGateway|SmsGateway $gateway, string $application, Authenticatable $recipient): void
    {
        GatewayAssert::assertLogsNothingOfTheMessage($gateway, self::messages($gateway, $application, $recipient));
    }

    /**
     * A delivery the provider fails, of every purpose, throws, delivers
     * nothing, and names neither the code nor the destination in its exception
     * or the log.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\EmailGateway|\SineMacula\Laravel\Iam\Contracts\SmsGateway  $gateway
     * @param  string  $application
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $recipient
     * @param  \Closure(): void  $fail
     * @param  \Closure(string): int  $delivered
     * @return void
     */
    public static function assertAFailureThrows(EmailGateway|SmsGateway $gateway, string $application, Authenticatable $recipient, \Closure $fail, \Closure $delivered): void
    {
        GatewayAssert::assertEachFailureThrows($gateway, self::messages($gateway, $application, $recipient), $fail, $delivered);
    }

    /**
     * The channel the contract's gateways deliver on.
     *
     * @return \SineMacula\Laravel\Iam\Delivery\Enums\Channel
     */
    abstract protected static function channel(): Channel;

    /**
     * The kit's messages on the contract's channel, for the application, once
     * the gateway is shown to be that channel's.
     *
     * @param  \SineMacula\Laravel\Iam\Contracts\EmailGateway|\SineMacula\Laravel\Iam\Contracts\SmsGateway  $gateway
     * @param  string  $application
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $recipient
     * @return list<\SineMacula\Laravel\Iam\Delivery\CodeMessage>
     */
    private static function messages(EmailGateway|SmsGateway $gateway, string $application, Authenticatable $recipient): array
    {
        $channel = static::channel();

        Assert::assertInstanceOf(DeliverySeams::contract($channel), $gateway, sprintf('The %s contract checks %s gateways only.', $channel->value, $channel->value));

        return GatewayAssert::messages($channel, $application, $recipient);
    }
}
