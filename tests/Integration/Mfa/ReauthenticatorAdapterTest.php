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
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
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
 * Tests for MFA's reauthenticator over the freshness policy.
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
     * The newest reauthentication on the session is answered.
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
        $reference  = ProofOwner::of($person);

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
     * A session with no reauthentication answers none.
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
     * A reauthentication answers until it is five minutes old.
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
     * The application's own setting makes the reauthentication stricter.
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
     * A session no longer live answers no reauthentication.
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
     * A session that cannot be resolved throws.
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
     * An unresolved session rolls back the transaction it is asked in.
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
     * Inside MFA's transaction the session row is the only lock it takes.
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
     * Outside a transaction it asks the policy plainly and takes no lock.
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
     * Inside a transaction it asks the policy current.
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
     * A reauthentication made after the transaction's first read is answered.
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
     * A signed-in person who has just proved their password again.
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
     * Prove the person's password again on the session.
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
