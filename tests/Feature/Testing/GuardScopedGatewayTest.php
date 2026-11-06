<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\GatewayTests;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\SmsGatewayTests;
use SineMacula\Laravel\Iam\Testing\Seams\GatewayAssert;
use SineMacula\Laravel\Iam\Testing\Seams\GatewayContract;
use SineMacula\Laravel\Iam\Testing\Seams\SmsGatewayContract;
use Tests\Fixtures\Delivery\ScriptedGateway;
use Tests\TestCase;

/**
 * Proves the `SmsGateway` contract kit against a gateway that serves named
 * guards only, choosing its sender by the guard each code is for and refusing
 * any other, as a gateway that brands its messages per application does: the
 * kit sends every message for the guard the test case names, so the gateway
 * passes as it runs, with no branch for the kit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SmsGatewayContract::class)]
#[CoversClass(GatewayContract::class)]
#[CoversClass(GatewayAssert::class)]
#[CoversTrait(SmsGatewayTests::class)]
#[CoversTrait(GatewayTests::class)]
final class GuardScopedGatewayTest extends TestCase
{
    use SmsGatewayTests;

    /** @var string The guard the gateway is proved for. */
    private const string SERVED = 'admin';

    /** @var ?\Tests\Fixtures\Delivery\ScriptedGateway The gateway under test. */
    private ?ScriptedGateway $gateway = null;

    /** @var list<string> The sender each delivery went out under, in order. */
    private array $senders = [];

    /**
     * Every message the contract gives the gateway is for the guard the test
     * case names, so each goes out under that guard's sender.
     *
     * @return void
     */
    public function testEveryMessageIsForTheGuardTheTestCaseNames(): void
    {
        SmsGatewayContract::assertDeliversEveryPurposeOnce($this->codeGateway(), $this->codeApplication(), $this->codeRecipient(), $this->codesDeliveredTo(...));

        self::assertNotEmpty($this->senders);
        self::assertSame(array_fill(0, count($this->senders), 'BrandAdmin'), $this->senders);
    }

    /**
     * The gateway under test.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\SmsGateway
     */
    #[\Override]
    protected function codeGateway(): SmsGateway
    {
        return $this->gateway ??= new ScriptedGateway(function (CodeMessage $message, ScriptedGateway $gateway): void {

            $sender = match ($message->application) {
                'web'        => 'Brand',
                self::SERVED => 'BrandAdmin',
                default      => throw new \DomainException('The gateway serves no such application.'),
            };

            if ($gateway->failing) {
                throw new \RuntimeException('The provider refused the message.');
            }

            $this->senders[] = $sender;

            $gateway->deliver($message);
        });
    }

    /**
     * The guard the gateway serves.
     *
     * @return string
     */
    #[\Override]
    protected function codeApplication(): string
    {
        return self::SERVED;
    }

    /**
     * The identity every message is for.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    protected function codeRecipient(): Authenticatable
    {
        return new GenericUser(['id' => 'guard-recipient']);
    }

    /**
     * How many messages the gateway delivered to the number.
     *
     * @param  string  $destination
     * @return int
     */
    #[\Override]
    protected function codesDeliveredTo(string $destination): int
    {
        $gateway = $this->codeGateway();

        assert($gateway instanceof ScriptedGateway);

        return $gateway->deliveredTo($destination);
    }

    /**
     * Tell the provider to fail the next delivery.
     *
     * @return void
     */
    #[\Override]
    protected function failCodeDelivery(): void
    {
        $gateway = $this->codeGateway();

        assert($gateway instanceof ScriptedGateway);

        $gateway->failing = true;
    }
}
