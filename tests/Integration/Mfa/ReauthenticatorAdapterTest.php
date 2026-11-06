<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\ReauthenticatorAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ReauthenticatorTests;
use Tests\Concerns\ChangesSessionsElsewhere;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RecordsFreshnessReadModes;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for MFA's reauthenticator over `laravel-authentication`'s
 * freshness policy (IAM-3.5): the newest reauthentication with the first factor
 * on the guard's current session, made within five minutes and no longer ago
 * than the application's own setting allows, is MFA's reauthentication, bound
 * to the identity, the application and the session; a session without one, or
 * no longer live, answers none; a guard holding no session of the identity, and
 * an application that is no guard, throw (IAM-8.2), rolling back the
 * transaction they are asked in; outside a transaction it asks the policy
 * plainly and takes no lock; and inside one, as MFA's own factor-change gate
 * asks it inside MFA's transaction, the only lock it takes is the session's,
 * last, and it asks the policy current, so a reauthentication made by another
 * request after the transaction's first read is found.
 *
 * The sessions are real ones, signed in and reauthenticated through
 * `laravel-authentication` with a password, and the adapter is resolved on its
 * own, so none of this package's other adapters takes part.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReauthenticatorAdapter::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class ReauthenticatorAdapterTest extends TestCase
{
    use ChangesSessionsElsewhere, MigratesMembers, ReauthenticatorTests, RecordsFreshnessReadModes, RunsAtIsolationLevels, SignsInPeople;

    /** @var string A locking read, of either server's grammar. */
    private const string LOCKING_READ = '/\b(for update|for share|for no key update|lock in share mode)\b/i';

    /**
     * The newest reauthentication on the guard's session is MFA's
     * reauthentication with the first factor, bound to the identity, the
     * application and the sign-in for `reauthenticate`, under the identity's
     * current verification generation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheNewestReauthenticationIsAnswered(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->reauthenticate($person, $session);
        $this->travel(10)->seconds();
        $this->reauthenticate($person, $session);

        $generation = VerificationGeneration::advance($person);
        $proof      = $this->adapter()->reauthenticate($person, self::GUARD);
        $reference  = IdentityReference::of($person);

        self::assertNotNull($proof);
        self::assertSame(ProofKind::FIRST_FACTOR_REAUTHENTICATION, $proof->kind);
        self::assertSame('password', $proof->method);
        self::assertSame(ChannelKind::PASSWORD, $proof->channel?->kind);
        self::assertTrue($proof->provedAt->equalTo(CarbonImmutable::now()->startOfSecond()));
        self::assertSame($reference->type, $proof->binding->identityType);
        self::assertSame($reference->key, $proof->binding->identityKey);
        self::assertSame(self::GUARD, $proof->binding->application);
        self::assertSame($this->signInReference($session), $proof->binding->sessionId);
        self::assertSame(Purpose::REAUTHENTICATE, $proof->binding->purpose);
        self::assertSame($generation, $proof->generation);
    }

    /**
     * A session holding only the sign-in's first factor has proved nothing
     * again, and answers no reauthentication.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWithNoReauthenticationAnswersNone(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        self::assertNull($this->adapter()->reauthenticate($person, self::GUARD));
    }

    /**
     * A reauthentication answers until it is five minutes old, and none from
     * then on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationFiveMinutesOldAnswersNone(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->reauthenticate($person, $session);

        $this->travel(299)->seconds();

        self::assertNotNull($this->adapter()->reauthenticate($person, self::GUARD));

        $this->travel(1)->seconds();

        self::assertNull($this->adapter()->reauthenticate($person, self::GUARD));
    }

    /**
     * The application's own setting for `first_additional_factor` makes the
     * reauthentication it takes stricter: a shorter age, and fewer kinds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationsSettingMakesItStricter(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->reauthenticate($person, $session);
        $this->travel(61)->seconds();

        Config::set('authentication.freshness.first_additional_factor', ['max_age_seconds' => 60, 'proofs' => ['first_factor_reauthentication']]);

        self::assertNull($this->adapter()->reauthenticate($person, self::GUARD));

        Config::set('authentication.freshness.first_additional_factor', ['max_age_seconds' => 900, 'proofs' => ['external_reauthentication']]);

        self::assertNull($this->adapter()->reauthenticate($person, self::GUARD));

        Config::set('authentication.freshness.first_additional_factor', ['max_age_seconds' => 900, 'proofs' => ['first_factor_reauthentication']]);

        self::assertNotNull($this->adapter()->reauthenticate($person, self::GUARD));
    }

    /**
     * A session revoked since the request was authenticated, which the guard
     * still holds, answers no reauthentication, though it recorded one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionNoLongerLiveAnswersNone(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->reauthenticate($person, $session);

        $session->newQuery()->whereKey($session->getKey())->update(['revoked_at' => CarbonImmutable::now()->subSecond(), 'revoked_reason' => 'signed_out']);

        self::assertNull($this->adapter()->reauthenticate($person, self::GUARD));
    }

    /**
     * A guard holding no session, one holding another identity's, and an
     * application that is no guard, cannot resolve the identity's session, and
     * throw.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatCannotBeResolvedThrows(): void
    {
        $person = $this->createPerson();

        self::assertUnresolved(fn (): mixed => $this->adapter()->reauthenticate($person, self::GUARD), self::GUARD);

        $this->signInAndActOnSession($this->createPerson());

        self::assertUnresolved(fn (): mixed => $this->adapter()->reauthenticate($person, self::GUARD), self::GUARD);
        self::assertUnresolved(fn (): mixed => $this->adapter()->reauthenticate($person, 'not-a-guard'), 'not-a-guard', ReferenceKind::GUARD);
    }

    /**
     * A session that cannot be resolved inside MFA's transaction rolls back
     * what the transaction wrote before it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnresolvedSessionRollsBackTheTransactionItIsAskedIn(): void
    {
        $person = $this->createPerson();

        self::assertUnresolved(fn (): mixed => DB::transaction(function () use ($person): ?Proof {

            VerificationGeneration::advance($person);

            return $this->adapter()->reauthenticate($person, self::GUARD);
        }), self::GUARD);

        self::assertSame(0, VerificationGeneration::current($person));
    }

    /**
     * Inside MFA's transaction, holding the identity's state row, the
     * reauthenticator locks the session's row before it reads the proof, and
     * takes no lock of MFA's, so it never takes a lock out of the order
     * identity state, factors, challenge, session row.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testTheSessionRowIsTheOnlyLockItTakes(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $locks   = [];

        $this->reauthenticate($person, $session);

        DB::transaction(function () use ($person, &$locks): void {

            VerificationGeneration::advance($person);

            DB::listen(static function (QueryExecuted $query) use (&$locks): void {

                if (preg_match(self::LOCKING_READ, $query->sql) !== 1) {
                    return;
                }

                $locks[] = $query->sql;
            });

            self::assertNotNull($this->adapter()->reauthenticate($person, self::GUARD));
        });

        self::assertNotSame([], array_filter($locks, static fn (string $sql): bool => str_contains($sql, $session->getTable())));
        self::assertSame([], array_filter($locks, static fn (string $sql): bool => str_contains($sql, 'mfa_')));
    }

    /**
     * Outside a transaction, as MFA's contract kit or a caller of the
     * application's asks it, nothing acts on the answer atomically: the
     * reauthenticator asks the policy plainly, which the policy answers there,
     * and takes no lock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOutsideATransactionItAsksPlainlyAndTakesNoLock(): void
    {
        $person   = $this->createPerson();
        $session  = $this->signInAndActOnSession($person);
        $recorder = $this->recordReadModes();
        $queries  = [];

        $this->reauthenticate($person, $session);

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        self::assertSame(0, DB::transactionLevel());
        self::assertNotNull($this->adapter()->reauthenticate($person, self::GUARD));
        self::assertAskedOnlyIn($recorder, false);
        self::assertNotSame([], $queries);
        self::assertSame([], array_filter($queries, static fn (string $sql): bool => preg_match(self::LOCKING_READ, $sql) === 1));
    }

    /**
     * Inside a transaction on the session model's connection, as MFA's own
     * factor-change gate asks it inside MFA's transaction and grants a first
     * additional factor on the answer, the reauthenticator asks the policy
     * current, which the policy answers there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideATransactionItAsksCurrent(): void
    {
        $person   = $this->createPerson();
        $session  = $this->signInAndActOnSession($person);
        $recorder = $this->recordReadModes();

        $this->reauthenticate($person, $session);

        self::assertNotNull(DB::transaction(fn (): ?Proof => $this->adapter()->reauthenticate($person, self::GUARD)));
        self::assertAskedOnlyIn($recorder, true);
    }

    /**
     * Inside a caller's transaction that read before another request proved the
     * person's password again on the session, that reauthentication is
     * answered, though the transaction's snapshot on MySQL at REPEATABLE READ
     * does not hold it. On PostgreSQL at REPEATABLE READ the session's lock
     * fails to serialise first, and the question asked again in a new
     * transaction is answered the same.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAReauthenticationMadeAfterTheTransactionsFirstReadIsAnswered(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        self::assertNull($this->adapter()->reauthenticate($person, self::GUARD));

        $proof = $this->askedAfter(
            $level,
            fn () => $this->reauthenticateElsewhere($person, $session),
            fn (): ?Proof => $this->adapter()->reauthenticate($person, self::GUARD),
        );

        self::assertInstanceOf(Proof::class, $proof);
        self::assertSame(ProofKind::FIRST_FACTOR_REAUTHENTICATION, $proof->kind);
        self::assertSame($this->signInReference($session), $proof->binding->sessionId);
    }

    /**
     * The reauthenticator under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\Reauthenticator
     */
    #[\Override]
    protected function reauthenticator(): Reauthenticator
    {
        return $this->adapter();
    }

    /**
     * A person signed in on the application who has just proved their password
     * again.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function reauthenticatingIdentity(): MultiFactorAuthenticatable
    {
        $person = $this->createPerson();

        $this->reauthenticate($person, $this->signInAndActOnSession($person));

        return $person;
    }

    /**
     * The application asked about.
     *
     * @return string
     */
    #[\Override]
    protected function reauthenticationApplication(): string
    {
        return self::GUARD;
    }

    /**
     * Prove the person's password again on the session, through
     * `laravel-authentication`, failing the test unless it is recorded.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     *
     * @throws \Throwable
     */
    private function reauthenticate(Person $person, EloquentSession&Model $session): void
    {
        $result = $this->sessions()->reauthenticate($session, 'password', ['email' => $person->email, 'password' => self::PASSWORD], self::client());

        self::assertTrue($result->isIssued(), sprintf('The person did not reauthenticate: [%s].', $result->reason?->value));
    }

    /**
     * Assert the call cannot resolve the identity's session on the application.
     *
     * @param  \Closure(): mixed  $call
     * @param  string  $application
     * @param  \SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind  $kind
     * @return void
     */
    private static function assertUnresolved(\Closure $call, string $application, ReferenceKind $kind = ReferenceKind::SESSION): void
    {
        try {
            $call();
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame($kind, $exception->kind);
            self::assertSame($application, $exception->application);

            return;
        }

        self::fail('The reauthenticator resolved a session.');
    }

    /**
     * Resolve the adapter under test from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\ReauthenticatorAdapter
     */
    private function adapter(): ReauthenticatorAdapter
    {
        $adapter = $this->app?->make(ReauthenticatorAdapter::class);

        self::assertInstanceOf(ReauthenticatorAdapter::class, $adapter);

        return $adapter;
    }
}
