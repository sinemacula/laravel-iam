<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Auth\User;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Mfa\SubjectTypeResolverAdapter;
use SineMacula\Laravel\Mfa\Context\IdentityContractSubjectType;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\SubjectTypeResolverTests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Machine;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\Factorless;
use Tests\TestCase;

/**
 * Integration tests for MFA's subject type read from `laravel-authentication`'s
 * machine identity contract (IAM-3.12): a machine identity is never a person,
 * though its model says it may hold factors, as MFA's own reading would take it
 * for one; any other identity is a person only when it is MFA's and may hold
 * factors; and once bound, MFA refuses a machine every operation it would
 * otherwise have run.
 *
 * The machine is the fixtures' `Machine`, which keeps MFA's own defaults, so
 * only the machine identity contract tells it apart from a person.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectTypeResolverAdapter::class)]
final class SubjectTypeResolverAdapterTest extends TestCase
{
    use MigratesMembers, SignsInPeople, SubjectTypeResolverTests;

    /**
     * A machine identity is no person, though its model says it may hold
     * factors and MFA's own reading takes it for one.
     *
     * @return void
     */
    public function testAMachineIsNoPersonWhateverItsModelSays(): void
    {
        $machine = new Machine;

        self::assertTrue($machine->canHoldFactors());
        self::assertTrue((new IdentityContractSubjectType)->isPerson($machine));
        self::assertFalse($this->adapter()->isPerson($machine));
    }

    /**
     * An identity MFA holds no factors for is no person: one whose model says
     * it may hold none, and one that is not MFA's identity at all.
     *
     * @return void
     */
    public function testAnIdentityMfaHoldsNoFactorsForIsNoPerson(): void
    {
        self::assertFalse($this->adapter()->isPerson(new Factorless));
        self::assertFalse($this->adapter()->isPerson(new User));
    }

    /**
     * Bound as MFA's subject type, the adapter has MFA refuse a machine an
     * operation, as one that is not a person, before anything is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfaRefusesAMachineOnceBound(): void
    {
        $this->app?->bind(SubjectTypeResolver::class, SubjectTypeResolverAdapter::class);

        $machine = Machine::query()->create(['name' => 'Build agent']);
        $actor   = Actor::of($this->createPerson());

        try {
            Mfa::resetIdentity($machine, $actor, 'Rotated credentials');

            self::fail('MFA reset a machine\'s factors.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::MACHINE_IDENTITY, $exception->reason);
        }

        Mfa::resetIdentity($this->createPerson(), $actor, 'Lost device');
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver
     */
    #[\Override]
    protected function subjectTypeResolver(): SubjectTypeResolver
    {
        return $this->adapter();
    }

    /**
     * A person's identity: the people who sign in on the guard.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    protected function personIdentity(): Authenticatable
    {
        return new Person;
    }

    /**
     * A machine's identity: an API client, declared as a machine identity.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    protected function machineIdentity(): Authenticatable
    {
        return new Machine;
    }

    /**
     * Resolve the adapter under test from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\SubjectTypeResolverAdapter
     */
    private function adapter(): SubjectTypeResolverAdapter
    {
        $adapter = $this->app?->make(SubjectTypeResolverAdapter::class);

        self::assertInstanceOf(SubjectTypeResolverAdapter::class, $adapter);

        return $adapter;
    }
}
