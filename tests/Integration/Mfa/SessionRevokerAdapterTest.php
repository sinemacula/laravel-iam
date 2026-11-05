<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\FactorRemoval;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\SessionMismatchException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\SessionRevokerTests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for MFA's session revoker through `laravel-authentication`
 * (IAM-3.7): MFA's contract kit, a removal that ends every other session, voids
 * the current session's proofs made with the factor and judges it again,
 * carrying `laravel-authentication`'s result and any new pending credential
 * back as MFA's completion, a reset that ends every session, and a removal from
 * another sign-in, or none, refused by throwing so the removal rolls back
 * (IAM-8.2).
 *
 * MFA's own flows are run too: removing a factor and resetting an identity,
 * with this package's factor-change adapters bound alone, end the sessions in
 * MFA's transaction, locking their rows after MFA's own, on MySQL and
 * PostgreSQL at READ COMMITTED and REPEATABLE READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevokerAdapter::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class SessionRevokerAdapterTest extends TestCase
{
    use ArrangesFactorChanges, MigratesMembers, RunsAtIsolationLevels, SessionRevokerTests, SignsInPeople;

    /** @var ?(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession) The session the guard acts on, removals' sign-in. */
    private (EloquentSession&Model)|null $current = null;

    /** @var ?(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession) Another session of the same person's. */
    private (EloquentSession&Model)|null $other = null;

    /**
     * A removal ends the other sessions and judges the current one itself,
     * carrying `laravel-authentication`'s result as the completion: the current
     * session still meets its requirement, so it stays active.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalEndsTheOthersAndJudgesTheCurrentSession(): void
    {
        $person = $this->revokedPerson();

        $this->verifyAnotherSession($person);

        $revocation = $this->revoker()->factorRemoved($person, 'factor-removed', $this->currentSessionOf($person));
        $removal    = $revocation->completion();

        self::assertTrue($revocation->judgedCurrent);
        self::assertInstanceOf(FactorRemoval::class, $removal);
        self::assertSame(1, $removal->revoked);
        self::assertFalse($removal->currentRevoked);
        self::assertFalse($removal->isPending());
        self::assertTrue($this->doesCurrentSessionCount($person));
        self::assertFalse($this->doesAnotherSessionCount($person));
    }

    /**
     * A current session that falls short once the factor is removed returns to
     * pending, and its new pending credential reaches MFA's removal result.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewPendingCredentialReachesTheRemovalResult(): void
    {
        $person = $this->revokedPerson();

        $this->requireAFurtherFactor();

        $removal = $this->revoker()->factorRemoved($person, 'factor-removed', $this->currentSessionOf($person))->completion();

        self::assertInstanceOf(FactorRemoval::class, $removal);
        self::assertTrue($removal->isPending());
        self::assertNotNull($removal->credential);
        self::assertSame($this->currentSessionOf($person), $removal->pending?->id);
        self::assertSame(SessionStatus::PENDING, $this->stored($this->currentSession())->getStatus());
    }

    /**
     * The proofs the current session made with the removed factor, named by
     * MFA's id for it, stop counting, and the others it holds are kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCurrentSessionsProofsMadeWithTheFactorAreVoided(): void
    {
        $person  = $this->revokedPerson();
        $removed = $this->confirmedFactor($person);
        $kept    = $this->confirmedFactor($person);

        $this->stepUpWith($person, $this->currentSession(), $kept->id);
        $this->stepUpWith($person, $this->currentSession(), $removed->id);

        $this->revoker()->factorRemoved($person, $removed->id, $this->currentSessionOf($person));

        $proofs = array_map(static fn (RecordedProof $proof): array => [$proof->kind, $proof->factor], $this->proofsOf($this->currentSession()));

        self::assertSame([[ProofKind::ADDITIONAL_FACTOR, $kept->id], [ProofKind::FIRST_FACTOR, null]], $proofs);
    }

    /**
     * Revoking every session ends the current one as well as the others.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingAllEndsTheCurrentSessionToo(): void
    {
        $person = $this->revokedPerson();

        $this->verifyAnotherSession($person);

        $this->revoker()->revokeAll($person);

        self::assertFalse($this->doesCurrentSessionCount($person));
        self::assertFalse($this->doesAnotherSessionCount($person));
    }

    /**
     * A removal from a sign-in that is not the guard's session, or with no
     * session on the guard, is refused inside the removal's transaction, which
     * rolls back: no session is ended, and what the removal wrote is gone.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARemovalFromAnotherSignInIsRefusedAndRollsBack(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person = $this->revokedPerson();

        $this->verifyAnotherSession($person);

        $refusals = [
            SessionMismatchException::class     => fn (): mixed => $this->revoker()->factorRemoved($person, 'factor-removed', $this->otherSessionOf()),
            UnresolvedReferenceException::class => function () use ($person): mixed {
                $this->stopActing(self::GUARD);

                return $this->revoker()->factorRemoved($person, 'factor-removed', $this->currentSessionOf($person));
            },
        ];

        foreach ($refusals as $refusal => $removal) {

            $this->assertRolledBack($person, $refusal, $removal);

            self::assertTrue($this->doesCurrentSessionCount($person));
            self::assertTrue($this->doesAnotherSessionCount($person));
        }
    }

    /**
     * An identity `laravel-authentication` does not sign in has no sessions to
     * end, so a removal and a reset are both refused.
     *
     * @return void
     */
    public function testAnIdentityThatIsNotLaravelAuthenticationsIsUnresolved(): void
    {
        $stranger = new class extends User implements MultiFactorAuthenticatable {
            use HasFactors;
        };

        self::assertSame(ReferenceKind::IDENTITY, self::unresolved(fn (): mixed => $this->revoker()->factorRemoved($stranger, 'factor-removed', 'sign-in'))->kind);
        self::assertSame(ReferenceKind::IDENTITY, self::unresolved(function () use ($stranger): void {
            $this->revoker()->revokeAll($stranger);
        })->kind);
    }

    /**
     * A default guard that holds no sessions names no application whose current
     * session a removal could be made from, so a removal is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADefaultGuardThatHoldsNoSessionsRefusesARemoval(): void
    {
        $person = $this->revokedPerson();

        Config::set('auth.defaults.guard', 'web');

        $exception = self::unresolved(fn (): mixed => $this->revoker()->factorRemoved($person, 'factor-removed', $this->currentSessionOf($person)));

        self::assertSame(ReferenceKind::GUARD, $exception->kind);
        self::assertSame('web', $exception->application);
        self::assertStringStartsWith('The application [web] is not a laravel-authentication guard', $exception->getMessage());

        Config::set('auth.defaults.guard', self::GUARD);

        self::assertTrue($this->doesCurrentSessionCount($person));
    }

    /**
     * A reset names no sign-in, so it is made wherever the default guard holds
     * no sessions (an admin panel's session guard, a console command, a queued
     * job) through the `jwt` guard declared: resetting an identity through MFA
     * then ends every session of it and removes its factors.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetMadeWhereTheDefaultGuardHoldsNoSessionsEndsEverySession(): void
    {
        $person = $this->revokedPerson();

        $this->confirmedFactor($person);
        $this->verifyAnotherSession($person);
        $this->bindTheFactorChangeAdapters();

        Config::set('auth.defaults.guard', 'web');

        Mfa::resetIdentity($person, Actor::of($this->createPerson()), 'Lost the phone the factor was on.');

        self::assertSame(0, Factor::query()->count());
        self::assertFalse($this->doesCurrentSessionCount($person));
        self::assertFalse($this->doesAnotherSessionCount($person));
    }

    /**
     * A reset goes through the default guard when it is a `jwt` guard, though
     * another is declared before it, so the guard bound to the identity forgets
     * its binding once the reset commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetGoesThroughTheDefaultGuardWhenItHoldsSessions(): void
    {
        $person = $this->revokedPerson();

        /** @var array<string, mixed> $guards */
        $guards = Config::get('auth.guards');

        Config::set('auth.guards', ['admin' => $guards[self::GUARD], ...$guards]);

        self::assertNotNull(Auth::guard(self::GUARD)->user());

        self::storage()->transaction(function () use ($person): void {
            $this->revoker()->revokeAll($person);
        });

        self::assertFalse($this->doesCurrentSessionCount($person));
        self::assertNull(Auth::guard(self::GUARD)->user());
    }

    /**
     * With no `jwt` guard declared at all, nothing names the sessions a reset
     * would end, so it is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetWithNoSessionGuardDeclaredIsUnresolved(): void
    {
        $person = $this->revokedPerson();

        /** @var array<string, mixed> $guards */
        $guards = Config::get('auth.guards');

        Config::set('auth.defaults.guard', 'web');
        Config::set('auth.guards', ['web' => $guards['web'], 'broken' => 'not a guard']);

        $exception = self::unresolved(function () use ($person): void {
            $this->revoker()->revokeAll($person);
        });

        self::assertSame(ReferenceKind::GUARD, $exception->kind);
        self::assertSame('web', $exception->application);

        Config::set('auth.defaults.guard', self::GUARD);
        Config::set('auth.guards', $guards);

        self::assertTrue($this->doesCurrentSessionCount($person));
    }

    /**
     * Removing a factor through MFA, with the factor-change adapters bound,
     * ends the other sessions in MFA's transaction, their rows locked after
     * MFA's locks on the identity's state and factors, and the current
     * session's new pending credential reaches the removal result.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testRemovingAFactorThroughMfaEndsTheOtherSessionsLast(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->revokedPerson();
        $removed = $this->confirmedFactor($person);
        $kept    = $this->confirmedFactor($person);

        $this->verifyAnotherSession($person);
        $this->bindTheFactorChangeAdapters();
        $this->nameTheSignIn($person, $this->currentSession());
        $this->stepUpWith($person, $this->currentSession(), $kept->id);
        $this->requireAFurtherFactor();

        DB::enableQueryLog();

        $result = Mfa::removeFactor($removed->id);

        $locks = array_values(array_filter(
            array_column(DB::getQueryLog(), 'query'),
            static fn (string $query): bool => str_contains($query, 'for update'),
        ));

        $sessions = array_keys(array_filter($locks, static fn (string $query): bool => str_contains($query, 'authentication_sessions')));
        $members  = array_keys(array_filter($locks, static fn (string $query): bool => str_contains($query, 'mfa_identity_states') || str_contains($query, 'mfa_factors')));

        self::assertTrue($result->wasMade());
        self::assertInstanceOf(FactorRemoval::class, $result->completion());
        self::assertTrue($result->completion()->isPending());
        self::assertNotNull($result->completion()->credential);
        self::assertFalse($this->doesAnotherSessionCount($person));
        self::assertNotSame([], $members);
        self::assertNotSame([], $sessions);
        self::assertGreaterThan(max($members), min($sessions));
        self::assertNull(Factor::query()->find($removed->id));
    }

    /**
     * Resetting an identity through MFA, with the factor-change adapters bound,
     * ends every session of it, the current one included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testResettingAnIdentityThroughMfaEndsEverySession(): void
    {
        $person = $this->revokedPerson();

        $this->confirmedFactor($person);
        $this->verifyAnotherSession($person);
        $this->bindTheFactorChangeAdapters();

        Mfa::resetIdentity($person, Actor::of($this->createPerson()), 'Lost the phone the factor was on.');

        self::assertSame(0, Factor::query()->count());
        self::assertFalse($this->doesCurrentSessionCount($person));
        self::assertFalse($this->doesAnotherSessionCount($person));
    }

    /**
     * The revoker under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\SessionRevoker
     */
    #[\Override]
    protected function sessionRevoker(): SessionRevoker
    {
        return $this->revoker();
    }

    /**
     * A person signed in on the guard, which acts on the session.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function revokedIdentity(): MultiFactorAuthenticatable
    {
        return $this->revokedPerson();
    }

    /**
     * The id of a confirmed factor of the person's.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return string
     */
    #[\Override]
    protected function removedFactorId(MultiFactorAuthenticatable $identity): string
    {
        self::assertInstanceOf(Person::class, $identity);

        return $this->confirmedFactor($identity)->id;
    }

    /**
     * The key of the session the guard acts on, as MFA names the sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return string
     */
    #[\Override]
    protected function currentSessionOf(MultiFactorAuthenticatable $identity): string
    {
        return $this->signInReference($this->currentSession());
    }

    /**
     * Whether the session the guard acts on is still one of its live, active
     * sessions.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function doesCurrentSessionCount(MultiFactorAuthenticatable $identity): bool
    {
        return $this->firstFactorOf($this->currentSession()) !== null;
    }

    /**
     * Sign the person in again, and act on the first session once more.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function verifyAnotherSession(MultiFactorAuthenticatable $identity): void
    {
        self::assertInstanceOf(Person::class, $identity);

        $this->other = $this->signIn($identity)->record;

        $this->actingOnSession($this->currentSession());
    }

    /**
     * Whether the other session is still one of the guard's live, active
     * sessions.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function doesAnotherSessionCount(MultiFactorAuthenticatable $identity): bool
    {
        self::assertNotNull($this->other);

        return $this->firstFactorOf($this->other) !== null;
    }

    /**
     * Create a person, sign them in and act on the session.
     *
     * @return \Tests\Fixtures\Models\Person
     *
     * @throws \Throwable
     */
    private function revokedPerson(): Person
    {
        $person = $this->createPerson();

        $this->current = $this->signInAndActOnSession($person);

        return $person;
    }

    /**
     * The session the guard acts on.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function currentSession(): EloquentSession&Model
    {
        self::assertNotNull($this->current);

        return $this->current;
    }

    /**
     * The key of the other session, as MFA names the sign-in.
     *
     * @return string
     */
    private function otherSessionOf(): string
    {
        self::assertNotNull($this->other);

        return $this->signInReference($this->other);
    }

    /**
     * The session as stored now.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function stored(EloquentSession&Model $session): Session
    {
        return Session::query()->whereKey($session->getKey())->firstOrFail();
    }

    /**
     * Assert the removal, made in a transaction on the storage connection after
     * the person's name was changed there, is refused with the exception given,
     * and that the change rolled back with it.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  class-string<\RuntimeException>  $refusal
     * @param  \Closure(): mixed  $removal
     * @return void
     *
     * @throws \Throwable
     */
    private function assertRolledBack(Person $person, string $refusal, \Closure $removal): void
    {
        try {
            self::storage()->transaction(static function () use ($person, $removal): void {

                $person->forceFill(['name' => 'Changed'])->save();

                $removal();
            });

            self::fail('A removal was made from a sign-in that is not the guard\'s session.');
        } catch (\RuntimeException $exception) {
            self::assertInstanceOf($refusal, $exception);
        }

        self::assertSame('Ada Lovelace', $person->refresh()->name);
    }

    /**
     * Assert the call is refused as an unresolved reference, and return the
     * refusal.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function unresolved(\Closure $call): UnresolvedReferenceException
    {
        try {
            $call();
        } catch (UnresolvedReferenceException $exception) {
            return $exception;
        }

        self::fail('Sessions were ended where none could be resolved.');
    }

    /**
     * Resolve the revoker under test from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter
     */
    private function revoker(): SessionRevokerAdapter
    {
        $revoker = $this->app?->make(SessionRevokerAdapter::class);

        self::assertInstanceOf(SessionRevokerAdapter::class, $revoker);

        return $revoker;
    }
}
