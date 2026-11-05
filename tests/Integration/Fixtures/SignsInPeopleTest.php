<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\TestCase;

/**
 * Integration tests for the fixtures every adapter test between
 * `laravel-authentication` and MFA starts from: the members' tables and the
 * people table exist on the storage connection, and a person signed in with a
 * password holds a live session whose first-factor proof is on the `password`
 * channel, which the guard is bound to.
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
final class SignsInPeopleTest extends TestCase
{
    use MigratesMembers, SignsInPeople;

    /**
     * A person signed in with a password holds a session whose only proof is
     * its first factor, made at sign-in on the `password` channel, and the
     * guard is bound to it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignedInPersonHoldsAFirstFactorOnThePasswordChannel(): void
    {
        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;

        $firstFactor = $this->firstFactorOf($session);
        $proofs      = $this->proofsOf($session);

        self::assertNotNull($firstFactor);
        self::assertSame(ProofKind::FIRST_FACTOR, $firstFactor->kind);
        self::assertSame(Purpose::SIGN_IN, $firstFactor->purpose);
        self::assertSame('password', $firstFactor->method);
        self::assertSame(ChannelKind::PASSWORD, $firstFactor->channel->kind);
        self::assertSame([$firstFactor->id], array_map(static fn ($proof): string => $proof->id, $proofs));

        $this->assertBoundIdentity($person, self::GUARD)->assertBoundSession($session, self::GUARD);
    }

    /**
     * Acting on an earlier session binds the guard to it, and MFA names its
     * sign-in by its key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testActingOnASessionBindsTheGuardToIt(): void
    {
        $person = $this->createPerson();
        $first  = $this->signIn($person)->record;

        $this->signIn($person);
        $this->actingOnSession($first, self::GUARD);

        $this->assertBoundSession($first, self::GUARD);

        $key = $first->getKey();

        self::assertIsScalar($key);
        self::assertSame((string) $key, $this->signInReference($first));
    }

    /**
     * Two people are created with addresses of their own, and a person given an
     * address keeps it.
     *
     * @return void
     */
    public function testEachPersonHasAnAddressOfTheirOwn(): void
    {
        self::assertNotSame($this->createPerson()->email, $this->createPerson()->email);
        self::assertSame('ada@example.test', $this->createPerson('Ada@Example.test')->email);
    }
}
