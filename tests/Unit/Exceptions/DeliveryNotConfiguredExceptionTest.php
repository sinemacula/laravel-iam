<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Exceptions\DeliveryNotConfiguredException;

/**
 * Unit tests for refusing a code no gateway can deliver (IAM-3.13): each
 * exception names the key to set and the channel or the type, and never the
 * code, the destination or the recipient.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliveryNotConfiguredException::class)]
final class DeliveryNotConfiguredExceptionTest extends TestCase
{
    /**
     * A channel with no gateway names the channel, its contract and its key.
     *
     * @return void
     */
    public function testAChannelWithNoGatewayNamesItsContractAndKey(): void
    {
        $exception = DeliveryNotConfiguredException::forChannel(Channel::SMS, SmsGateway::class, 'iam.delivery.sms');

        self::assertSame(
            'No sms gateway is bound as ' . SmsGateway::class . ' or named in iam.delivery.sms, so the code cannot be delivered:'
            . ' name the application\'s gateway there, or bind it before this package registers.',
            $exception->getMessage(),
        );
        self::assertSame(Channel::SMS, $exception->channel);
        self::assertNull($exception->type);
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }

    /**
     * A gateway named by something that is no gateway names the key, what it
     * names and the contract.
     *
     * @return void
     */
    public function testAGatewayThatIsNoneNamesWhatTheKeyNames(): void
    {
        $exception = DeliveryNotConfiguredException::forGateway(Channel::EMAIL, EmailGateway::class, 'iam.delivery.email', 'App\Mail');

        self::assertSame(
            'iam.delivery.email names [App\Mail], which is not a class implementing ' . EmailGateway::class . ', so the code cannot be delivered.',
            $exception->getMessage(),
        );
        self::assertSame(Channel::EMAIL, $exception->channel);
        self::assertNull($exception->type);
    }

    /**
     * A binding that resolves to what is no gateway of its channel names the
     * binding, what it resolves to, the channel and the contract, and no
     * configuration key.
     *
     * @return void
     */
    public function testABindingThatIsNoGatewayNamesWhatItResolvesTo(): void
    {
        $exception = DeliveryNotConfiguredException::forBinding(Channel::SMS, SmsGateway::class, SmsGateway::class, 'App\Mail');

        self::assertSame(
            'The container binding of ' . SmsGateway::class . ' resolves to [App\Mail], which is no gateway of the sms channel,'
            . ' so the code cannot be delivered: bind it to a class implementing ' . SmsGateway::class . '.',
            $exception->getMessage(),
        );
        self::assertSame(Channel::SMS, $exception->channel);
        self::assertNull($exception->type);
    }

    /**
     * A type that routes to no channel names the type and the routes' key.
     *
     * @return void
     */
    public function testATypeThatRoutesNowhereNamesTheType(): void
    {
        $exception = DeliveryNotConfiguredException::forType('username', 'iam.delivery.types');

        self::assertSame(
            'A code to a destination of type [username] routes to no gateway, so it cannot be delivered:'
            . ' iam.delivery.types maps each of laravel-authentication\'s identifier types to `email` or `sms`,'
            . ' and a further factor\'s code goes out on its own channel, `email` or `sms`.',
            $exception->getMessage(),
        );
        self::assertNull($exception->channel);
        self::assertSame('username', $exception->type);
    }
}
