<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Testing\Concerns\RecordsGatewayMessages;
use SineMacula\Laravel\Iam\Testing\FakeSmsGateway;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\GatewayTests;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\SmsGatewayTests;
use SineMacula\Laravel\Iam\Testing\Seams\GatewayAssert;
use SineMacula\Laravel\Iam\Testing\Seams\GatewayContract;
use SineMacula\Laravel\Iam\Testing\Seams\LogRecorder;
use SineMacula\Laravel\Iam\Testing\Seams\SmsGatewayContract;
use Tests\TestCase;

/**
 * Proves the `SmsGateway` contract kit against this package's fake SMS gateway
 * (IAM-3.13): the fake delivers a message of every purpose once, logs nothing
 * of it, and throws, keeping nothing, when told to fail.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeSmsGateway::class)]
#[CoversClass(SmsGatewayContract::class)]
#[CoversClass(GatewayContract::class)]
#[CoversClass(GatewayAssert::class)]
#[CoversClass(LogRecorder::class)]
#[CoversTrait(RecordsGatewayMessages::class)]
#[CoversTrait(SmsGatewayTests::class)]
#[CoversTrait(GatewayTests::class)]
final class FakeSmsGatewayTest extends TestCase
{
    use SmsGatewayTests;

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeSmsGateway The gateway under test, bound as the application's. */
    private ?FakeSmsGateway $gateway = null;

    /**
     * The fake, bound as the application's SMS gateway.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\SmsGateway
     */
    #[\Override]
    protected function codeGateway(): SmsGateway
    {
        return $this->fake();
    }

    /**
     * The application the fake is proved for.
     *
     * @return string
     */
    #[\Override]
    protected function codeApplication(): string
    {
        return GatewayAssert::APPLICATION;
    }

    /**
     * The identity every message is for.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    protected function codeRecipient(): Authenticatable
    {
        return new GenericUser(['id' => 'contract-recipient']);
    }

    /**
     * How many messages the fake keeps for the number.
     *
     * @param  string  $number
     * @return int
     */
    #[\Override]
    protected function codesDeliveredTo(string $number): int
    {
        return count($this->fake()->sentTo($number));
    }

    /**
     * Tell the fake to fail its next delivery.
     *
     * @return void
     */
    #[\Override]
    protected function failCodeDelivery(): void
    {
        $this->fake()->failNext();
    }

    /**
     * The fake the kit runs against, bound as the application's SMS gateway the
     * first time it is asked for.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeSmsGateway
     */
    private function fake(): FakeSmsGateway
    {
        return $this->gateway ??= FakeSmsGateway::fake($this->app);
    }
}
