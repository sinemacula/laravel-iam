<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Testing\Concerns\RecordsGatewayMessages;

/**
 * An SMS gateway for tests: keeps every code message it is given instead of
 * delivering it, whichever member issued the code, so a test can read the code
 * and verify with it, and see the purpose, the member, the application and the
 * recipient it was sent for; `failNext()` makes the next delivery throw, as a
 * provider's failure would.
 *
 * Name it in `iam.delivery.sms` before this package registers, so the members'
 * senders are pointed at the gateway, then call `FakeSmsGateway::fake()`, which
 * binds a fresh instance as the application's gateway and returns it. A code of
 * `laravel-authentication`'s arrives when its queued delivery job runs. It
 * satisfies this package's own `Seams\Concerns\SmsGatewayTests` kit. Not for
 * production use.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeSmsGateway implements SmsGateway
{
    use RecordsGatewayMessages;

    /** @var class-string The contract the fake is bound as. */
    public const string GATEWAY = SmsGateway::class;
}
