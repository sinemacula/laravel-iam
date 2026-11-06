<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Machine;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for the identities the context adapters read (IAM-3.12): a
 * person is active until the test clears the flag, and keeps a phone number in
 * its normal form; a machine is `laravel-authentication`'s machine identity,
 * though MFA's own defaults would take it for a person that may hold factors.
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
final class IdentitiesTest extends TestCase
{
    use MigratesMembers, SignsInPeople;

    /**
     * A new person is active, and stays inactive once the flag is cleared, read
     * back from the database.
     *
     * @return void
     */
    public function testAPersonIsActiveUntilTheFlagIsCleared(): void
    {
        $person = $this->createPerson();

        self::assertTrue($person->isActive());

        $person->forceFill(['is_active' => false])->save();

        self::assertFalse(Person::query()->findOrFail($person->id)->isActive());
    }

    /**
     * A person's phone number is kept in its normal form.
     *
     * @return void
     */
    public function testAPersonsPhoneNumberIsKeptInItsNormalForm(): void
    {
        $person = $this->createPerson();

        $person->forceFill(['phone' => ' +447700900123 '])->save();

        self::assertSame('+447700900123', Person::query()->findOrFail($person->id)->phone);
    }

    /**
     * A machine is `laravel-authentication`'s machine identity, while MFA's own
     * defaults take it for a person that may hold factors and is active.
     *
     * @return void
     */
    public function testAMachineIsAMachineIdentity(): void
    {
        $machine = Machine::query()->create(['name' => 'Billing export']);

        self::assertInstanceOf(MachineIdentity::class, Machine::query()->findOrFail($machine->id));
        self::assertTrue($machine->canHoldFactors());
        self::assertTrue($machine->isMfaActive());
    }
}
