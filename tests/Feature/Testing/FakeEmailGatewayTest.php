<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Testing\Concerns\RecordsGatewayMessages;
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\EmailGatewayTests;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\GatewayTests;
use SineMacula\Laravel\Iam\Testing\Seams\EmailGatewayContract;
use SineMacula\Laravel\Iam\Testing\Seams\GatewayAssert;
use SineMacula\Laravel\Iam\Testing\Seams\GatewayContract;
use SineMacula\Laravel\Iam\Testing\Seams\LogRecorder;
use Tests\TestCase;

/**
 * Proves the `EmailGateway` contract kit against this package's fake email
 * gateway (IAM-3.13): the fake delivers a message of every purpose once, logs
 * nothing of it, and throws, keeping nothing, when told to fail.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeEmailGateway::class)]
#[CoversClass(EmailGatewayContract::class)]
#[CoversClass(GatewayContract::class)]
#[CoversClass(GatewayAssert::class)]
#[CoversClass(LogRecorder::class)]
#[CoversTrait(RecordsGatewayMessages::class)]
#[CoversTrait(EmailGatewayTests::class)]
#[CoversTrait(GatewayTests::class)]
final class FakeEmailGatewayTest extends TestCase
{
    use EmailGatewayTests;

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeEmailGateway The gateway under test, bound as the application's. */
    private ?FakeEmailGateway $gateway = null;

    /**
     * The fake, bound as the application's email gateway.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\EmailGateway
     */
    #[\Override]
    protected function codeGateway(): EmailGateway
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
     * How many messages the fake keeps for the address.
     *
     * @param  string  $address
     * @return int
     */
    #[\Override]
    protected function codesDeliveredTo(string $address): int
    {
        return count($this->fake()->sentTo($address));
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
     * The fake the kit runs against, bound as the application's email gateway
     * the first time it is asked for.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeEmailGateway
     */
    private function fake(): FakeEmailGateway
    {
        return $this->gateway ??= FakeEmailGateway::fake($this->app);
    }
}
