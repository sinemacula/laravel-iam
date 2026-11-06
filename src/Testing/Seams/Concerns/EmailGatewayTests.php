<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams\Concerns;

use SineMacula\Laravel\Iam\Testing\Seams\EmailGatewayContract;

/**
 * The `EmailGateway` contract kit: a message is delivered once, nothing of it
 * is logged, and a failure throws, each checked by `EmailGatewayContract`.
 *
 * A test case proves the application's email gateway by using this trait and
 * implementing the hooks `GatewayTests` declares: `codeGateway()` answers the
 * email gateway, `codeApplication()` names the guard it serves, and
 * `codesDeliveredTo()` counts what reached an address, in its normal form.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait EmailGatewayTests
{
    use GatewayTests;

    /**
     * The email gateway contract.
     *
     * @return class-string<\SineMacula\Laravel\Iam\Testing\Seams\GatewayContract>
     */
    #[\Override]
    private function gatewayContract(): string
    {
        return EmailGatewayContract::class;
    }
}
