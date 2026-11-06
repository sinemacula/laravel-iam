<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Delivery\DeliverySettings;
use SineMacula\Laravel\Iam\Delivery\EmailSenderAdapter;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\MfaSenderAdapter;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;

/**
 * Unit tests for MFA's email sender pointed at the application's email gateway
 * (IAM-3.13).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EmailSenderAdapter::class)]
#[CoversClass(MfaSenderAdapter::class)]
final class EmailSenderAdapterTest extends MfaSenderAdapterTestCase
{
    /**
     * The email channel.
     *
     * @return \SineMacula\Laravel\Iam\Delivery\Enums\Channel
     */
    #[\Override]
    protected static function channel(): Channel
    {
        return Channel::EMAIL;
    }

    /**
     * MFA's email sender, this package's adapter.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\DeliverySettings  $settings
     * @return \SineMacula\Laravel\Mfa\Contracts\EmailSender
     */
    #[\Override]
    protected function senderOver(DeliverySettings $settings): EmailSender
    {
        return new EmailSenderAdapter($settings);
    }
}
