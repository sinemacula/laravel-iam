<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams\Concerns;

use SineMacula\Laravel\Iam\Testing\Seams\SmsGatewayContract;

/**
 * The `SmsGateway` contract kit: a message is delivered once, nothing of it is
 * logged, and a failure throws, each checked by `SmsGatewayContract`.
 *
 * A test case proves the application's SMS gateway by using this trait and
 * implementing the hooks `GatewayTests` declares: `codeGateway()` answers the
 * SMS gateway, `codeApplication()` names the guard it serves, and
 * `codesDeliveredTo()` counts what reached a number, in E.164 form.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait SmsGatewayTests
{
    use GatewayTests;

    /**
     * The SMS gateway contract.
     *
     * @return class-string<\SineMacula\Laravel\Iam\Testing\Seams\GatewayContract>
     */
    #[\Override]
    private function gatewayContract(): string
    {
        return SmsGatewayContract::class;
    }
}
