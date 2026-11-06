<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Delivery\DeliverySettings;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\MfaSenderAdapter;
use SineMacula\Laravel\Iam\Delivery\SmsSenderAdapter;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;

/**
 * Unit tests for MFA's SMS sender pointed at the application's SMS gateway
 * (IAM-3.13).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SmsSenderAdapter::class)]
#[CoversClass(MfaSenderAdapter::class)]
final class SmsSenderAdapterTest extends MfaSenderAdapterTestCase
{
    /**
     * The SMS channel.
     *
     * @return \SineMacula\Laravel\Iam\Delivery\Enums\Channel
     */
    #[\Override]
    protected static function channel(): Channel
    {
        return Channel::SMS;
    }

    /**
     * MFA's SMS sender, this package's adapter.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\DeliverySettings  $settings
     * @return \SineMacula\Laravel\Mfa\Contracts\SmsSender
     */
    #[\Override]
    protected function senderOver(DeliverySettings $settings): SmsSender
    {
        return new SmsSenderAdapter($settings);
    }
}
