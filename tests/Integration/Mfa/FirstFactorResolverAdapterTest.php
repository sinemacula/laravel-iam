<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\FirstFactorResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Mfa\SignInProofs;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\FirstFactorResolverTests;
use Tests\Concerns\FindsLockedSessions;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\TestCase;

/**
 * Tests for MFA's first-factor resolver over the identity's current session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FirstFactorResolverAdapter::class)]
#[CoversClass(ProofStoreAdapter::class)]
#[CoversClass(SignInProofs::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class FirstFactorResolverAdapterTest extends TestCase
{
    use FindsLockedSessions, FirstFactorResolverTests, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /**
     * The first factor is the session's own, bound to the session for sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFirstFactorIsTheSessionsOwn(): void
    {
        $person = $this->createPerson();

        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());

        $session    = $this->signInAndActOnSession($person);
        $generation = VerificationGeneration::advance($person);
        $proof      = $this->firstFactorResolver()->resolve($person, self::GUARD);

        self::assertNotNull($proof);
        self::assertSame(ProofKind::FIRST_FACTOR, $proof->kind);
        self::assertSame('password', $proof->method);
        self::assertEquals(new Channel(ChannelKind::PASSWORD), $proof->channel);
        self::assertNull($proof->reference);
        self::assertEquals(CarbonImmutable::now(), $proof->provedAt);
        self::assertSame($generation, $proof->generation);
        self::assertSame(
            [$person->getMorphClass(), ProofOwner::of($person)->key, self::GUARD, $this->signInReference($session), Purpose::SIGN_IN],
            [$proof->binding->identityType, $proof->binding->identityKey, $proof->binding->application, $proof->binding->sessionId, $proof->binding->purpose],
        );
    }

    /**
     * Nothing is answered without a live session of the identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingIsAnsweredWithoutALiveSessionOfTheIdentity(): void
    {
        $person   = $this->createPerson();
        $resolver = $this->firstFactorResolver();

        $this->signInAndActOnSession($this->createPerson());

        self::assertNull($resolver->resolve($person, self::GUARD));

        $session = $this->signInAndActOnSession($person);

        $adapter = $this->app?->make(FirstFactorResolverAdapter::class);

        self::assertInstanceOf(FirstFactorResolverAdapter::class, $adapter);

        try {
            $adapter->resolve($person, 'not-a-guard');

            self::fail('A first factor was answered for an application that is no session guard.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::GUARD, $exception->kind);
        }

        $this->sessions()->revokeSession($person, $session->getKey(), RevocationReason::REVOKED);

        self::assertNull($resolver->resolve($person, self::GUARD));
    }

    /**
     * An identity whose key cannot name a proof's owner throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutAKeyIsUnresolved(): void
    {
        $stranger = new class extends User implements MultiFactorAuthenticatable {
            use HasFactors;
        };

        $this->signInAndActOnSession($this->createPerson());

        $resolver = $this->app?->make(FirstFactorResolverAdapter::class);

        self::assertInstanceOf(FirstFactorResolverAdapter::class, $resolver);

        $this->expectException(UnsupportedIdentifierException::class);

        $resolver->resolve($stranger, self::GUARD);
    }

    /**
     * Inside the caller's transaction the session's row is locked last.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testResolvingLocksTheSessionRowLastInTheCallersTransaction(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$resolver, $person] = [$this->firstFactorResolver(), $this->createPerson()];

        $session = $this->signInAndActOnSession($person);

        DB::connection(StorageConnection::name())->transaction(function () use ($resolver, $person, $session): void {

            VerificationGeneration::advance($person);

            self::assertFalse($this->isLockedElsewhere($session));
            self::assertNotNull($resolver->resolve($person, self::GUARD));
            self::assertTrue($this->isLockedElsewhere($session));
        });

        self::assertFalse($this->isLockedElsewhere($session));
        self::assertNotNull($resolver->resolve($person, self::GUARD));
        self::assertFalse($this->isLockedElsewhere($session));
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
    }

    /**
     * An unresolved sign-in rolls the caller's transaction back.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAnUnresolvedSignInRollsTheCallersTransactionBack(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$resolver, $person] = [$this->firstFactorResolver(), $this->createPerson()];

        $session    = $this->signInAndActOnSession($person);
        $generation = VerificationGeneration::current($person);

        try {
            DB::connection(StorageConnection::name())->transaction(static function () use ($resolver, $person): void {

                VerificationGeneration::advance($person);
                $person->forceFill(['name' => 'Changed'])->save();

                self::assertNotNull($resolver->resolve($person, self::GUARD));

                $resolver->resolve($person, 'not-a-guard');
            });

            self::fail('A first factor was answered for an application that is no session guard.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::GUARD, $exception->kind);
        }

        self::assertSame($generation, VerificationGeneration::current($person));
        self::assertSame('Ada Lovelace', $person->fresh()?->getAttribute('name'));
        self::assertFalse($this->isLockedElsewhere($session));
    }

    /**
     * The resolver under test, resolved from the container.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver
     */
    #[\Override]
    protected function firstFactorResolver(): FirstFactorResolver
    {
        $resolver = $this->app?->make(FirstFactorResolverAdapter::class);

        self::assertInstanceOf(FirstFactorResolverAdapter::class, $resolver);

        return $resolver;
    }

    /**
     * A person signed in, the guard acting on the session.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function signedInIdentity(): MultiFactorAuthenticatable
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        return $person;
    }

    /**
     * A person who has not signed in.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function identityWithoutSignIn(): MultiFactorAuthenticatable
    {
        return $this->createPerson();
    }

    /**
     * The guard asked about.
     *
     * @return string
     */
    #[\Override]
    protected function firstFactorApplication(): string
    {
        return self::GUARD;
    }
}
