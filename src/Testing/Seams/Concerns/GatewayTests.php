<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;

/**
 * The checks a gateway contract kit runs, whichever channel the gateway
 * delivers on: a message is delivered once, nothing of it is logged, and a
 * failure throws.
 *
 * A test case uses it through `EmailGatewayTests` or `SmsGatewayTests`, which
 * name the channel's contract, and implements the hooks against the provider's
 * own test double (a faked HTTP client or mail transport, say), so the hooks
 * can count what reached a destination and make the next delivery fail; each
 * check delegates to the channel's contract. It runs in a Laravel test case,
 * whose log it reads, so the test case must not fake the log's `MessageLogged`
 * event (as `Event::fake()` with no list does), or the checks that read the log
 * fail. One test case proves one gateway.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait GatewayTests
{
    /**
     * A message of every purpose, from either member, is delivered exactly
     * once.
     *
     * @return void
     */
    public function testGatewayDeliversEveryPurposeOnce(): void
    {
        $this->gatewayContract()::assertDeliversEveryPurposeOnce($this->codeGateway(), $this->codeApplication(), $this->codeRecipient(), $this->codesDeliveredTo(...));
    }

    /**
     * Delivering a message logs neither its code nor its destination.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGatewayLogsNothingOfTheMessage(): void
    {
        $this->gatewayContract()::assertLogsNothingOfTheMessage($this->codeGateway(), $this->codeApplication(), $this->codeRecipient());
    }

    /**
     * A delivery the provider fails throws and delivers nothing.
     *
     * @return void
     */
    public function testGatewayThrowsWhenDeliveryFails(): void
    {
        $this->gatewayContract()::assertAFailureThrows(
            $this->codeGateway(),
            $this->codeApplication(),
            $this->codeRecipient(),
            $this->failCodeDelivery(...),
            $this->codesDeliveredTo(...),
        );
    }

    /**
     * The gateway under test, of the contract's channel.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\EmailGateway|\SineMacula\Laravel\Iam\Contracts\SmsGateway
     */
    abstract protected function codeGateway(): EmailGateway|SmsGateway;

    /**
     * The application every message is for: the guard the gateway serves, as
     * each member names it on a code it issues.
     *
     * @return string
     */
    abstract protected function codeApplication(): string;

    /**
     * The identity every message is for.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    abstract protected function codeRecipient(): Authenticatable;

    /**
     * How many messages the gateway has delivered to the destination, in its
     * normal form: an address, or a number in E.164 form.
     *
     * @param  string  $destination
     * @return int
     */
    abstract protected function codesDeliveredTo(string $destination): int;

    /**
     * Make the provider fail the gateway's next delivery.
     *
     * @return void
     */
    abstract protected function failCodeDelivery(): void;

    /**
     * The contract of the gateway's channel, which `EmailGatewayTests` and
     * `SmsGatewayTests` name.
     *
     * @return class-string<\SineMacula\Laravel\Iam\Testing\Seams\GatewayContract>
     */
    abstract private function gatewayContract(): string;
}
