<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Proofs\Channel as AuthenticationChannel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind as AuthenticationProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties as AuthenticationProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding as AuthenticationBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ProofStoreTests;
use Tests\Concerns\FindsLockedSessions;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Factors\NumberedFactor;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for MFA's proof store kept in `laravel-authentication`'s
 * session proofs (IAM-3.11): a sign-in is the guard's current session, its
 * proofs are the session's counting proofs, oldest first and bound to it, and a
 * proof is refused unless it is bound to the identity's current, live sign-in,
 * checked under the session's lock inside the caller's transaction.
 *
 * MFA's `ProofStoreTests` kit runs on real sessions, through its hooks for a
 * store whose proofs and sign-ins the authentication layer alone writes. Each
 * check's sign-in is signed in through `laravel-authentication` with a
 * password, and the guard then stops acting on it, so the store holds no
 * sign-in and no proof of the identity until a check arranges one: the password
 * first factor the check arranges is the one `laravel-authentication` recorded
 * on signing the session in, which counts once the guard acts on the session,
 * as the bearer request after a sign-in does, and which the store then keeps
 * when the check's proof is recorded through it (it refuses any other); a
 * further factor is recorded through `laravel-authentication`'s step-up, the
 * only way it records one on an active session, with a factor MFA holds for the
 * identity. A sign-in ends when `laravel-authentication` signs the session out,
 * and its proofs are voided as a reset voids them, through `factorReset()`.
 *
 * The kit forgets a factor the identity still holds, which the store reports to
 * `laravel-authentication` as the factor's removal; a factor MFA has already
 * deleted, as it does before forgetting one, stops counting at once, before
 * `laravel-authentication` voids its proofs, and is checked here as well.
 *
 * The lock and rollback cases run at READ COMMITTED and REPEATABLE READ on
 * MySQL and PostgreSQL, and are skipped on SQLite. The members' defaults stay
 * bound: the store is resolved directly, so none of this package's other
 * adapters takes part.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofStoreAdapter::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class ProofStoreAdapterTest extends TestCase
{
    use FindsLockedSessions, MigratesMembers, ProofStoreTests, RunsAtIsolationLevels, SignsInPeople;

    /** @var string A factor the identity never held, which no proof made with it counts. */
    private const string FACTOR = 'factor-never-held';

    /** @var ?\Tests\Fixtures\Models\Person The identity the kit's checks sign in. */
    private ?Person $person = null;

    /** @var (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null The session the kit's check signed in. */
    private (EloquentSession&Model)|null $kitSession = null;

    /**
     * A factor MFA has deleted stops counting as soon as it is forgotten, and
     * only it, though `laravel-authentication` still holds its proofs until the
     * session revoker reports the removal, inside MFA's transaction as outside
     * it; a further proof is refused by the store, which only
     * `laravel-authentication` records.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAForgottenFactorStopsCountingAtOnce(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $record  = $this->signInAndActOnSession($person);
        $session = $this->signInReference($record);

        [$forgotten, $kept] = [$this->factorOf($person), $this->factorOf($person)];

        self::assertRefused(static fn () => $store->record(self::additionalFactor($person, $session, $forgotten->id)));

        $this->stepUp($person, $record, AuthenticationProofKind::ADDITIONAL_FACTOR, $forgotten->id);
        $this->stepUp($person, $record, AuthenticationProofKind::ADDITIONAL_FACTOR, $kept->id);

        self::assertSame([null, $forgotten->id, $kept->id], self::references($store->proofs($person, self::GUARD)));

        DB::connection(StorageConnection::name())->transaction(function () use ($store, $person, $forgotten, $kept): void {

            VerificationGeneration::advance($person);

            $forgotten->delete();
            $store->forgetFactor($person, $forgotten->id);

            self::assertSame([null, $kept->id], self::references($store->proofs($person, self::GUARD)));
        });

        self::assertCount(3, $this->proofsOf($record));
        self::assertSame([null, $kept->id], self::references($store->proofs($person, self::GUARD)));

        $this->sessions()->factorRemoved($person, $forgotten->id, $record);

        self::assertCount(2, $this->proofsOf($record));
        self::assertSame([null, $kept->id], self::references($store->proofs($person, self::GUARD)));
    }

    /**
     * A factor deleted inside a transaction that then rolls back counts again:
     * the store keeps nothing of its own about it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorDeletedInATransactionRolledBackCountsAgain(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $record = $this->signInAndActOnSession($person);
        $factor = $this->factorOf($person);

        $this->stepUp($person, $record, AuthenticationProofKind::ADDITIONAL_FACTOR, $factor->id);

        try {
            DB::connection(StorageConnection::name())->transaction(function () use ($store, $person, $factor): void {

                $factor->delete();
                $store->forgetFactor($person, $factor->id);

                self::assertSame([null], self::references($store->proofs($person, self::GUARD)));

                throw new \RuntimeException('Rolled back.');
            });
        } catch (\RuntimeException) {
            // The factor's deletion is undone with the transaction.
        }

        self::assertSame([null, $factor->id], self::references($store->proofs($person, self::GUARD)));
    }

    /**
     * A first factor the session recorded as made with one of MFA's factors (a
     * passkey associated as a factor, say) is the sign-in's first factor while
     * the identity holds that factor, and none once it does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFirstFactorMadeWithAFactorNoLongerHeldIsNone(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $record = $this->signInAndActOnSession($person);
        $factor = $this->factorOf($person);

        DB::table('authentication_proofs')->where('session_id', $record->getKey())->update(['factor_reference' => $factor->id]);

        self::assertSame($factor->id, $store->firstFactor($person, self::GUARD)?->reference);
        self::assertSame([$factor->id], self::references($store->proofs($person, self::GUARD)));

        $factor->delete();

        self::assertNull($store->firstFactor($person, self::GUARD));
        self::assertSame([], $store->proofs($person, self::GUARD));
    }

    /**
     * A factor whose identifier is a number is the one a proof naming that
     * number as text was made with.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorIdentifiedByANumberIsMatchedAsText(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        Config::set('mfa.factor.model', NumberedFactor::class);

        $record = $this->signInAndActOnSession($person);
        $number = (string) NumberedFactor::NUMBER;

        $this->factorOf($person);
        $this->stepUp($person, $record, AuthenticationProofKind::ADDITIONAL_FACTOR, $number);

        self::assertSame([null, $number], self::references($store->proofs($person, self::GUARD)));
    }

    /**
     * The identity's factors are read only when a proof names one, and then
     * once, on the write connection, however many proofs name one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFactorsAreReadOnlyWhenAProofNamesOne(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $record = $this->signInAndActOnSession($person);
        $factor = $this->factorOf($person);

        $this->stepUp($person, $record, AuthenticationProofKind::RECOVERY_CODE);

        self::assertSame(0, $this->factorReads(static fn () => $store->proofs($person, self::GUARD)));
        self::assertSame(0, $this->factorReads(static fn () => $store->firstFactor($person, self::GUARD)));
        self::assertSame([ProofKind::FIRST_FACTOR, ProofKind::RECOVERY_CODE], self::kinds($store->proofs($person, self::GUARD)));

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSecond());

        $this->stepUp($person, $record, AuthenticationProofKind::ADDITIONAL_FACTOR, $factor->id);
        $this->stepUp($person, $record, AuthenticationProofKind::ADDITIONAL_FACTOR, $factor->id);

        self::assertSame(1, $this->factorReads(static fn () => $store->proofs($person, self::GUARD)));
    }

    /**
     * The current sign-in is the key of the guard's current session, whatever
     * sign-in MFA began.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCurrentSignInIsTheGuardsSession(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $session = $this->signInAndActOnSession($person);
        $held    = $store->proofs($person, self::GUARD);

        $store->begin($person, self::GUARD, Str::lower((string) Str::ulid()));

        self::assertSame($this->signInReference($session), $store->currentSession($person, self::GUARD));
        self::assertEquals($held, $store->proofs($person, self::GUARD));
    }

    /**
     * An identity the guard holds no session of has no current sign-in and no
     * proofs: with no session, with another identity's, and once the guard has
     * stopped acting on it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityTheGuardHoldsNoSessionOfHasNoSignIn(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $store->begin($person, self::GUARD, 'any-sign-in');

        self::assertNoSignIn($store, $person, self::GUARD);

        $this->signInAndActOnSession($this->createPerson());

        self::assertNoSignIn($store, $person, self::GUARD);

        $this->signInAndActOnSession($person);
        $this->stopActing(self::GUARD);

        self::assertNoSignIn($store, $person, self::GUARD);
    }

    /**
     * An application that is no session guard of `laravel-authentication`'s, an
     * `api_key` guard among them, is a misconfiguration, not a guard holding no
     * sign-in: asking about it throws (IAM-8.2) rather than answering that
     * nothing counts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationThatIsNoSessionGuardIsUnresolved(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $this->signInAndActOnSession($person);

        config()->set('auth.guards.keys', ['driver' => 'api_key', 'provider' => 'people']);

        foreach (['not-a-guard', 'keys'] as $application) {
            foreach (
                [
                    static fn (): mixed => $store->currentSession($person, $application),
                    static fn (): mixed => $store->proofs($person, $application),
                ] as $question
            ) {
                try {
                    $question();

                    self::fail(sprintf('A sign-in was answered for [%s], which is no session guard.', $application));
                } catch (UnresolvedReferenceException $exception) {
                    self::assertSame(ReferenceKind::GUARD, $exception->kind);
                    self::assertSame($application, $exception->application);
                }
            }
        }
    }

    /**
     * The session's counting proofs are MFA's, oldest first, each bound to the
     * identity, the application and the session for the purpose it was made
     * for, under the identity's current verification generation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSessionsProofsAreTranslatedOldestFirst(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());

        $record = $this->signInAndActOnSession($person);
        $signIn = CarbonImmutable::now();
        $factor = $this->factorOf($person)->id;

        CarbonImmutable::setTestNow($signIn->addSecond());

        $observed = new AuthenticationProperties(userPresence: true, backupEligible: true, phishingResistant: false);

        $this->stepUp($person, $record, AuthenticationProofKind::ADDITIONAL_FACTOR, $factor, $observed);

        CarbonImmutable::setTestNow($signIn->addSeconds(2));

        $this->stepUp($person, $record, AuthenticationProofKind::RECOVERY_CODE);

        $generation = VerificationGeneration::advance($person);
        $proofs     = $store->proofs($person, self::GUARD);

        self::assertSame([ProofKind::FIRST_FACTOR, ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], self::kinds($proofs));
        self::assertSame(['password', 'totp', 'recovery_code'], array_map(static fn (Proof $proof): string => $proof->method, $proofs));
        self::assertEquals([$signIn, $signIn->addSecond(), $signIn->addSeconds(2)], array_map(static fn (Proof $proof): CarbonImmutable => $proof->provedAt, $proofs));
        self::assertSame([Purpose::SIGN_IN, Purpose::STEP_UP, Purpose::STEP_UP], array_map(static fn (Proof $proof): Purpose => $proof->binding->purpose, $proofs));
        $channels = [new Channel(ChannelKind::PASSWORD), new Channel(ChannelKind::AUTHENTICATOR_APP, $factor), null];

        self::assertEquals($channels, array_map(static fn (Proof $proof): ?Channel => $proof->channel, $proofs));
        self::assertSame([null, $factor, null], self::references($proofs));
        self::assertTrue($proofs[1]->properties->userPresence);
        self::assertTrue($proofs[1]->properties->backupEligibility);
        self::assertFalse($proofs[1]->properties->phishingResistance);

        foreach ($proofs as $proof) {
            self::assertSame(
                [$person->getMorphClass(), self::keyOf($person), self::GUARD, $this->signInReference($record)],
                [$proof->binding->identityType, $proof->binding->identityKey, $proof->binding->application, $proof->binding->sessionId],
            );
            self::assertSame($generation, $proof->generation);
        }
    }

    /**
     * A proof the session holds that MFA cannot express (an additional factor
     * naming no factor), or that names a factor the identity does not hold, is
     * left out, not guessed at.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofMfaCannotExpressDoesNotCount(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $record = $this->signInAndActOnSession($person);

        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond()->addSecond());

        $this->stepUp($person, $record, AuthenticationProofKind::ADDITIONAL_FACTOR);

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSecond());

        $this->stepUp($person, $record, AuthenticationProofKind::RECOVERY_CODE);

        self::assertSame([ProofKind::FIRST_FACTOR, ProofKind::RECOVERY_CODE], self::kinds($store->proofs($person, self::GUARD)));

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSecond());

        $this->stepUp($person, $record, AuthenticationProofKind::ADDITIONAL_FACTOR, self::FACTOR);

        self::assertCount(4, $this->proofsOf($record));
        self::assertSame([ProofKind::FIRST_FACTOR, ProofKind::RECOVERY_CODE], self::kinds($store->proofs($person, self::GUARD)));
    }

    /**
     * A session revoked while the guard still holds it keeps no proof that
     * counts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevokedSessionKeepsNoProof(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $record = $this->signInAndActOnSession($person);

        $this->sessions()->revokeSession($person, $record->getKey(), RevocationReason::REVOKED);

        self::assertSame($this->signInReference($record), $store->currentSession($person, self::GUARD));
        self::assertSame([], $store->proofs($person, self::GUARD));
    }

    /**
     * An identity whose key cannot name a proof's owner is not resolved: it
     * throws rather than reading another identity's sign-in (IAM-8.2).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutAKeyIsUnresolved(): void
    {
        $store    = $this->proofStore();
        $stranger = new class extends User implements MultiFactorAuthenticatable {
            use HasFactors;
        };

        $this->signInAndActOnSession($this->createPerson());

        foreach ([static fn () => $store->currentSession($stranger, self::GUARD), static fn () => $store->proofs($stranger, self::GUARD)] as $read) {

            try {
                $read();

                self::fail('An identity without a key was resolved.');
            } catch (UnresolvedReferenceException $exception) {
                self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
            }
        }
    }

    /**
     * The sign-in's own first factor is kept, already held by the session, and
     * any proof it does not hold is refused and not kept: another identity's,
     * another sign-in's, an application's that is no session guard, a first
     * factor made otherwise than the session's, and a further proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheSignInsOwnFirstFactorIsKept(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $session = $this->signInReference($this->signInAndActOnSession($person));
        $held    = $store->proofs($person, self::GUARD);

        $store->record(self::firstFactor($person, $session));

        $password = new Channel(ChannelKind::PASSWORD);
        $email    = new Channel(ChannelKind::EMAIL, 'a@example.test');
        $refused  = [
            'another identity\'s'    => self::firstFactor($this->createPerson(), $session),
            'another sign-in\'s'     => self::firstFactor($person, 'another-' . $session),
            'no session guard\'s'    => self::firstFactor($person, $session, 'not-a-guard'),
            'a passkey first factor' => self::proof($person, $session, ProofKind::FIRST_FACTOR, 'passkey', new Channel(ChannelKind::PASSKEY), null, Purpose::SIGN_IN),
            'a code first factor'    => self::proof($person, $session, ProofKind::FIRST_FACTOR, 'password', $email, null, Purpose::SIGN_IN),
            'a further factor'       => self::additionalFactor($person, $session, self::FACTOR),
            'a reauthentication'     => self::proof($person, $session, ProofKind::FIRST_FACTOR_REAUTHENTICATION, 'password', $password, null, Purpose::REAUTHENTICATE),
        ];

        foreach ($refused as $case => $proof) {
            self::assertRefused(static fn () => $store->record($proof), $case);
        }

        self::assertEquals($held, $store->proofs($person, self::GUARD));
    }

    /**
     * A proof is refused when the guard holds no session, acts as the identity
     * on none, or holds another identity's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofIsRefusedWithoutTheIdentitysSession(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $session = $this->signInReference($this->signIn($person)->record);

        $this->stopActing(self::GUARD);

        self::assertRefused(static fn () => $store->record(self::firstFactor($person, $session)), 'no session');

        $this->actingAsIdentity($person, guard: self::GUARD);

        self::assertRefused(static fn () => $store->record(self::firstFactor($person, $session)), 'no session the guard acts on');

        $this->signInAndActOnSession($this->createPerson());

        self::assertRefused(static fn () => $store->record(self::firstFactor($person, $session)), 'another identity\'s session');
    }

    /**
     * A proof bound to a session that is no longer live and active is refused,
     * though the guard still holds it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofOfARevokedSessionIsRefused(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $record = $this->signInAndActOnSession($person);

        $this->sessions()->revokeSession($person, $record->getKey(), RevocationReason::REVOKED);

        self::assertRefused(fn () => $store->record(self::firstFactor($person, $this->signInReference($record))));
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
    }

    /**
     * Beginning and forgetting a sign-in write nothing, and forgetting a factor
     * the identity does not hold only reads its factors: the session keeps its
     * proofs until `laravel-authentication` voids them, and a factor the
     * identity still holds keeps counting.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testForgettingAndBeginningWriteNothing(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $record = $this->signInAndActOnSession($person);
        $factor = $this->factorOf($person)->id;

        $this->stepUp($person, $record, AuthenticationProofKind::ADDITIONAL_FACTOR, $factor);

        $held = $store->proofs($person, self::GUARD);

        DB::enableQueryLog();

        $store->begin($person, self::GUARD, 'another-sign-in');
        $store->forget($person, self::GUARD);

        $quiet = DB::getQueryLog();

        DB::flushQueryLog();

        self::assertSame(1, $this->factorReads(static fn () => $store->forgetFactor($person, self::FACTOR)));
        self::assertSame([], $quiet);
        self::assertSame(['select'], array_map(static fn (array $query): string => strtok($query['query'], ' ') ?: '', DB::getQueryLog()));

        self::assertSame([null, $factor], self::references($held));
        self::assertEquals($held, $store->proofs($person, self::GUARD));
        self::assertSame($this->signInReference($record), $store->currentSession($person, self::GUARD));
    }

    /**
     * Forgetting a factor the identity still holds is reported to
     * `laravel-authentication` as its removal: the current session's proofs
     * made with it are voided there, and only those, the session is judged
     * again and stays active on the factor it still holds, and every other
     * session of the identity ends; the factor itself is left to MFA.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testForgettingAHeldFactorVoidsItsProofsThroughAuthentication(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $other  = $this->signIn($person)->record;
        $record = $this->signInAndActOnSession($person);

        [$forgotten, $kept] = [$this->factorOf($person), $this->factorOf($person)];

        $this->stepUp($person, $record, AuthenticationProofKind::ADDITIONAL_FACTOR, $forgotten->id);
        $this->stepUp($person, $record, AuthenticationProofKind::ADDITIONAL_FACTOR, $kept->id);

        self::assertCount(3, $this->proofsOf($record));
        self::assertNotNull($this->firstFactorOf($other));

        $store->forgetFactor($person, $forgotten->id);

        self::assertCount(2, $this->proofsOf($record));
        self::assertSame([null, $kept->id], self::references($store->proofs($person, self::GUARD)));
        self::assertNotNull($this->firstFactorOf($record));
        self::assertNull($this->firstFactorOf($other));
        self::assertTrue($forgotten->newQuery()->whereKey($forgotten->getKey())->exists());
    }

    /**
     * Forgetting a factor the identity still holds, when the default guard
     * holds no session of the identity, ends every session it has, so no proof
     * made with the factor counts anywhere.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testForgettingAHeldFactorWithoutASessionEndsEverySession(): void
    {
        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $record = $this->signIn($person)->record;
        $factor = $this->factorOf($person);

        $this->stopActing(self::GUARD);

        self::assertNotNull($this->firstFactorOf($record));

        $store->forgetFactor($person, $factor->id);

        self::assertNull($this->firstFactorOf($record));
    }

    /**
     * Recording inside the caller's transaction, after the caller's own locks
     * (MFA's identity state), locks the session's row last, until the caller's
     * transaction ends; recording outside one opens and ends its own.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testRecordingLocksTheSessionRowLastInTheCallersTransaction(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $record = $this->signInAndActOnSession($person);
        $proof  = self::firstFactor($person, $this->signInReference($record));

        DB::connection(StorageConnection::name())->transaction(function () use ($store, $person, $record, $proof): void {

            VerificationGeneration::advance($person);

            self::assertFalse($this->isLockedElsewhere($record));

            $store->record($proof);

            self::assertTrue($this->isLockedElsewhere($record));
        });

        self::assertFalse($this->isLockedElsewhere($record));

        $store->record($proof);

        self::assertFalse($this->isLockedElsewhere($record));
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
    }

    /**
     * A refusal inside the caller's transaction rolls back everything the
     * caller wrote in it.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARefusalRollsTheCallersTransactionBack(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $record = $this->signInAndActOnSession($person);

        $this->sessions()->revokeSession($person, $record->getKey(), RevocationReason::REVOKED);

        $generation = VerificationGeneration::current($person);

        self::assertRefused(fn () => DB::connection(StorageConnection::name())->transaction(function () use ($store, $person, $record): void {

            VerificationGeneration::advance($person);
            $person->forceFill(['name' => 'Changed'])->save();

            $store->record(self::firstFactor($person, $this->signInReference($record)));
        }));

        self::assertSame($generation, VerificationGeneration::current($person));
        self::assertSame('Ada Lovelace', $person->fresh()?->getAttribute('name'));
    }

    /**
     * A session revoked by another transaction after the caller's began is read
     * current under its lock: the proof is refused, or, at PostgreSQL's
     * REPEATABLE READ, the caller's transaction fails to serialise, for its
     * owner to retry whole.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASessionRevokedConcurrentlyIsReadCurrent(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$store, $person] = [$this->proofStore(), $this->createPerson()];

        $record     = $this->signInAndActOnSession($person);
        $proof      = self::firstFactor($person, $this->signInReference($record));
        $connection = DB::connection(StorageConnection::name());
        $serialises = $connection->getDriverName() === 'pgsql' && $level === 'repeatable read';

        try {
            $connection->transaction(function () use ($store, $person, $record, $proof): void {

                // A plain read takes the transaction's snapshot and locks
                // nothing the other connection's revocation waits on.
                self::assertNotNull($person->fresh());

                $this->other()
                    ->table($record->getTable())
                    ->where($record->getKeyName(), $record->getKey())
                    ->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => RevocationReason::REVOKED->value]);

                $store->record($proof);
            });

            self::fail('A proof of a session revoked concurrently was kept.');
        } catch (ProofRefusedException) {
            self::assertFalse($serialises, 'PostgreSQL at REPEATABLE READ must fail to serialise instead.');
        } catch (QueryException $exception) {
            self::assertTrue($serialises, $exception->getMessage());
            self::assertSame('40001', $exception->getCode());
        }
    }

    /**
     * The proof store under test, resolved from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter
     */
    #[\Override]
    protected function proofStore(): ProofStoreAdapter
    {
        $store = $this->app?->make(ProofStoreAdapter::class);

        self::assertInstanceOf(ProofStoreAdapter::class, $store);

        return $store;
    }

    /**
     * The person the kit's checks sign in.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function proofStoreIdentity(): MultiFactorAuthenticatable
    {
        return $this->person ??= $this->createPerson();
    }

    /**
     * The guard the kit's sign-ins are on.
     *
     * @return string
     */
    #[\Override]
    protected function proofStoreApplication(): string
    {
        return self::GUARD;
    }

    /**
     * Sign the identity in through `laravel-authentication` for real, and name
     * the session as MFA names the sign-in, with the guard no longer acting on
     * it, so the store holds no sign-in of the identity until the check
     * arranges its first factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return string
     *
     * @throws \Throwable
     */
    protected function proofStoreSignIn(MultiFactorAuthenticatable $identity, string $application): string
    {
        self::assertInstanceOf(Person::class, $identity);

        $this->kitSession = $this->signIn($identity, $application)->record;

        $this->stopActing($application);

        return $this->signInReference($this->kitSession, $application);
    }

    /**
     * Put the check's proof in the sign-in through `laravel-authentication`.
     *
     * A password first factor is the one `laravel-authentication` recorded on
     * signing the session in, its only first factor: the guard acts on the
     * session, as the bearer request after a sign-in does, so it counts, and
     * the check's proof is recorded through the store, which keeps it only as
     * that session's own first factor. A further factor is recorded through
     * `laravel-authentication`'s step-up, the one way it records one on an
     * active session, made with the same factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \Throwable
     */
    protected function arrangeProofStoreProof(ProofStore $store, MultiFactorAuthenticatable $identity, string $application, string $session, Proof $proof): void
    {
        $record = $this->kitSession ?? self::fail('The check arranged a proof before signing in.');

        self::assertInstanceOf(Person::class, $identity);
        self::assertSame($this->signInReference($record, $application), $session);

        if ($proof->kind === ProofKind::FIRST_FACTOR) {
            $this->actingOnSession($record, $application);

            $store->record($proof);

            return;
        }

        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proof->kind);
        self::assertSame('totp', $proof->method);

        $this->stepUp($identity, $record, AuthenticationProofKind::ADDITIONAL_FACTOR, $proof->reference);
    }

    /**
     * Sign the identity out through `laravel-authentication`, which revokes the
     * session and forgets the guard's binding to it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     *
     * @throws \Throwable
     */
    protected function endProofStoreSignIn(ProofStore $store, MultiFactorAuthenticatable $identity, string $application): void
    {
        self::assertTrue($this->sessions($application)->signOut());
    }

    /**
     * Enrol a confirmed factor of MFA's for the identity, and name it as a
     * proof made with it names it: the store counts such a proof only while the
     * identity holds the factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return string
     */
    protected function proofStoreFactor(MultiFactorAuthenticatable $identity): string
    {
        self::assertInstanceOf(Person::class, $identity);

        return ProofStoreAdapter::factorReference($this->factorOf($identity));
    }

    /**
     * Void the identity's proofs as a reset voids them: by ending every session
     * it has through `laravel-authentication`'s `factorReset()`.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \Throwable
     */
    protected function voidProofStoreProofs(MultiFactorAuthenticatable $identity): void
    {
        self::assertInstanceOf(Identity::class, $identity);

        $this->sessions()->factorReset($identity);
    }

    /**
     * The factor each proof names, in order.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<?string>
     */
    private static function references(array $proofs): array
    {
        return array_map(static fn (Proof $proof): ?string => $proof->reference, $proofs);
    }

    /**
     * A confirmed TOTP factor of the person's, stored as MFA stores one.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factorOf(Person $person): Factor
    {
        $model = config('mfa.factor.model');

        self::assertTrue(is_a($model, Factor::class, true));

        return $model::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => self::keyOf($person),
            'status'               => FactorStatus::CONFIRMED->value,
            'application'          => self::GUARD,
            'confirmed_at'         => CarbonImmutable::now(),
        ]);
    }

    /**
     * How many times the work reads MFA's factor table, failing the test if any
     * read is not on the write connection.
     *
     * @param  \Closure(): mixed  $work
     * @return int
     */
    private function factorReads(\Closure $work): int
    {
        $reads = [];

        DB::listen(static function (QueryExecuted $query) use (&$reads): void {

            if (!str_contains($query->sql, (new Factor)->getTable())) {
                return;
            }

            $reads[] = $query->readWriteType;
        });

        $work();

        foreach ($reads as $type) {
            self::assertSame('write', $type);
        }

        return count($reads);
    }

    /**
     * The person's key, as MFA names the owner of a proof.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return string
     */
    private static function keyOf(Person $person): string
    {
        return IdentityReference::of($person)->key;
    }

    /**
     * Assert the identity has no current sign-in on the application, and no
     * proofs.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    private static function assertNoSignIn(ProofStore $store, MultiFactorAuthenticatable $identity, string $application): void
    {
        self::assertNull($store->currentSession($identity, $application));
        self::assertSame([], $store->proofs($identity, $application));
    }

    /**
     * Assert the work is refused with MFA's `ProofRefusedException`.
     *
     * @param  \Closure(): mixed  $work
     * @param  string  $case
     * @return void
     */
    private static function assertRefused(\Closure $work, string $case = 'the proof'): void
    {
        try {
            $work();

            self::fail(sprintf('The proof store kept %s.', $case));
        } catch (ProofRefusedException $exception) {
            self::assertNotSame('', $exception->getMessage());
        }
    }

    /**
     * The kind of each proof, in order.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<\SineMacula\Laravel\Mfa\Enums\ProofKind>
     */
    private static function kinds(array $proofs): array
    {
        return array_map(static fn (Proof $proof): ProofKind => $proof->kind, $proofs);
    }

    /**
     * A password first factor of the identity, bound to the sign-in.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $session
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function firstFactor(Person $person, string $session, string $application = self::GUARD): Proof
    {
        return self::proof($person, $session, ProofKind::FIRST_FACTOR, 'password', new Channel(ChannelKind::PASSWORD), null, Purpose::SIGN_IN, $application);
    }

    /**
     * An authenticator app proof of the factor, bound to the sign-in.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $session
     * @param  string  $factor
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function additionalFactor(Person $person, string $session, string $factor): Proof
    {
        return self::proof($person, $session, ProofKind::ADDITIONAL_FACTOR, 'totp', new Channel(ChannelKind::AUTHENTICATOR_APP, $factor), $factor, Purpose::SIGN_IN);
    }

    /**
     * A proof of the person made now, bound to the sign-in.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\ProofKind  $kind
     * @param  string  $method
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  ?string  $reference
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function proof(
        Person $person,
        string $session,
        ProofKind $kind,
        string $method,
        Channel $channel,
        ?string $reference,
        Purpose $purpose,
        string $application = self::GUARD,
    ): Proof {
        return new Proof(
            kind      : $kind,
            method    : $method,
            channel   : $channel,
            reference : $reference,
            properties: ObservedProperties::none(),
            provedAt  : CarbonImmutable::now(),
            binding   : new ProofBinding($person->getMorphClass(), self::keyOf($person), $application, $session, $purpose),
            generation: 0,
        );
    }

    /**
     * Step the session up through `laravel-authentication` with a further proof
     * of the person's, accepted as multifactor, as the step-up adapter hands
     * one over.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @param  ?string  $factor
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @return void
     *
     * @throws \Throwable
     */
    private function stepUp(Person $person, EloquentSession&Model $session, AuthenticationProofKind $kind, ?string $factor = null, ?AuthenticationProperties $observed = null): void
    {
        $recovery = $kind === AuthenticationProofKind::RECOVERY_CODE;
        $channel  = $recovery ? new AuthenticationChannel(AuthenticationChannelKind::UNKNOWN) : new AuthenticationChannel(AuthenticationChannelKind::AUTHENTICATOR_APP, $factor);

        $result = $this->sessions()->stepUp(new ProofResult(
            $kind,
            $recovery ? 'recovery_code' : 'totp',
            $channel,
            $factor,
            $observed ?? new AuthenticationProperties,
            new Evaluation(true, true),
            [$recovery ? 'kba' : 'otp'],
            CarbonImmutable::now(),
            new AuthenticationBinding($person, self::GUARD, $session->getKey(), AuthenticationPurpose::STEP_UP),
        ));

        self::assertTrue($result->isIssued(), sprintf('The step-up was refused: [%s].', $result->reason->value ?? 'none'));
    }
}
