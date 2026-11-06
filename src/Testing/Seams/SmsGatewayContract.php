<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams;

use SineMacula\Laravel\Iam\Delivery\Enums\Channel;

/**
 * What every `SmsGateway` must guarantee, as assertions (see
 * `GatewayContract`): a message of every purpose is delivered once to its
 * number, a delivery logs neither the code nor the number, and a failure
 * throws. The messages go to E.164 numbers of the kit's own, from the range set
 * aside for drama.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class SmsGatewayContract extends GatewayContract
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
}
