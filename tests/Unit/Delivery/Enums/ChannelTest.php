<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;

/**
 * Unit tests for the channels a code goes out on, the gateway names
 * `iam.delivery.types` routes to, and the members a code comes from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Channel::class)]
#[CoversClass(Source::class)]
final class ChannelTest extends TestCase
{
    /**
     * The channels are email and SMS, in that order, each backed by the name of
     * its gateway.
     *
     * @return void
     */
    public function testTheChannelsAreEmailAndSms(): void
    {
        self::assertSame(['email', 'sms'], array_column(Channel::cases(), 'value'));
    }

    /**
     * A code comes from `laravel-authentication` or MFA, in that order.
     *
     * @return void
     */
    public function testACodeComesFromAuthenticationOrMfa(): void
    {
        self::assertSame(['authentication', 'mfa'], array_column(Source::cases(), 'value'));
    }
}
