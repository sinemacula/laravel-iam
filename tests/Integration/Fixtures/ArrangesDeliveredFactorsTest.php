<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Codes\Concerns\ArrangesDeliveredFactors;
use Tests\TestCase;

/**
 * Integration tests for the delivered factors code challenges are sent for
 * (IAM-3.9): a confirmed SMS factor goes to the fixtures' number, a pending
 * email factor to the person's own address, and either to a destination the
 * test names, all on the application people sign in on.
 *
 * They run against the members' own defaults, so they show the fixtures work
 * whatever state this package's adapters are in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class ArrangesDeliveredFactorsTest extends TestCase
{
    use ArrangesDeliveredFactors, MigratesMembers, SignsInPeople;

    /**
     * A confirmed SMS factor is the person's, on the application, and goes to
     * the fixtures' number.
     *
     * @return void
     */
    public function testAConfirmedSmsFactorGoesToTheFixturesNumber(): void
    {
        $person = $this->createPerson();
        $factor = $this->deliveredFactor($person);

        self::assertSame([$factor->id], $person->authFactors()->pluck('id')->all());
        self::assertSame('sms', $factor->getType());
        self::assertSame(self::DELIVERED_PHONE, $factor->destination);
        self::assertSame(FactorStatus::CONFIRMED->value, $factor->status);
        self::assertSame(self::GUARD, $factor->application);
        self::assertNotNull($factor->confirmed_at);
    }

    /**
     * A pending email factor goes to the person's own address, and is not
     * confirmed.
     *
     * @return void
     */
    public function testAPendingEmailFactorGoesToThePersonsAddress(): void
    {
        $person = $this->createPerson();
        $factor = Factor::query()->findOrFail($this->pendingDeliveredFactor($person, 'email')->id);

        self::assertSame('email', $factor->getType());
        self::assertSame($person->email, $factor->destination);
        self::assertSame(FactorStatus::PENDING->value, $factor->status);
        self::assertNull($factor->confirmed_at);
    }

    /**
     * A delivered factor goes to the destination the test names.
     *
     * @return void
     */
    public function testADeliveredFactorGoesToTheDestinationNamed(): void
    {
        $factor = $this->deliveredFactor($this->createPerson(), 'sms', '+447700900999');

        self::assertSame('+447700900999', $factor->destination);
    }
}
