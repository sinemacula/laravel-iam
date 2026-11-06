<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams;

use SineMacula\Laravel\Iam\Delivery\Enums\Channel;

/**
 * What every `EmailGateway` must guarantee, as assertions (see
 * `GatewayContract`): a message of every purpose is delivered once to its
 * address, a delivery logs neither the code nor the address, and a failure
 * throws. The messages go to addresses of the kit's own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class EmailGatewayContract extends GatewayContract
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
}
