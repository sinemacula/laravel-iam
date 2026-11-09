<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as ProofPurpose;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\LinkCallers;
use SineMacula\Laravel\Iam\Sso\LinkConfirmationAdapter;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\ChangesSessionsElsewhere;
use Tests\Concerns\FindsLockedSessions;
use Tests\Concerns\LinksByVerifiedDomain;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RegistersPasskeys;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for SSO's link confirmation over `laravel-authentication`'s
 * public reader of a session's proofs (IAM-4.10, IAM-13.9), against SSO's
 * acceptance scenario: a person whose only session came through a verified
 * domain link is `independent_authentication_required` when confirming it, and
 * a password or passkey session confirms.
 *
 * A session is `independent` only when it signed in with a password, a passkey
 * or the application's own recovery (a `start()` under a method named at
 * `iam.sso.recovery_methods`), was never renewed through a provider, is the
 * caller's own, handed in as a plain value, and is judged inside a transaction,
 * where its row is locked and its proofs read current until the transaction
 * ends. Everything else is `dependent`: a session through the domain link, a
 * `start()` under another method, a session renewed through a provider, revoked
 * (here or on another connection after the transaction began), another person's
 * or held through a refresh credential, a caller who is not the identity asked
 * about, no caller, and any judgement outside a transaction.
 *
 * Every redemption, and every judgement read inside a transaction, runs at the
 * connection's own level on every engine, then at READ COMMITTED and REPEATABLE
 * READ on MySQL and PostgreSQL; the lock and the revocation on another
 * connection run at those two levels alone, and the judgement outside a
 * transaction, which reads nothing, at the connection's own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkConfirmationAdapter::class)]
#[CoversClass(LinkCallers::class)]
#[CoversClass(SsoSeams::class)]
#[WithConfig(TenancyContracts::MEMBERSHIPS, FakeMemberships::class, defer: false)]
final class LinkConfirmationAdapterTest extends TestCase
{
    use ChangesSessionsElsewhere, FindsLockedSessions, LinksByVerifiedDomain, MigratesSso, RegistersPasskeys, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The sign-in method of the application's own recovery in these tests. */
    private const string RECOVERY = 'account_recovery';

    /** @var ?\Tests\Fixtures\Models\Person The member of the tenant the domain links. */
    private ?Person $person = null;

    /** @var (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null The member's password session, once a test signs them in. */
    private (EloquentSession&Model)|null $passwordSession = null;

    /**
     * Arrange SSO, with the tenant's domain verified for its connection and a
     * member of the tenant of that domain's verified email.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $memberships = FakeMemberships::fake($this->app);

        $this->person = $this->createVerifiedPerson();

        $memberships->grant($this->person, Membership::of(self::TENANT, CarbonImmutable::now()->subDays(2)));

        $this->verifyDomain();
        $this->grantsWithin();
    }

    /**
     * The adapter is the link confirmation SSO resolves, in place of SSO's
     * refusing default.
     *
     * @return void
     */
    public function testTheAdapterIsSsosLinkConfirmation(): void
    {
        self::assertInstanceOf(LinkConfirmationAdapter::class, $this->resolved(LinkConfirmation::class));
    }

    /**
     * A person whose session came through their verified domain link is refused
     * as `independent_authentication_required` when confirming that link, which
     * keeps its verified domain provenance.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testASessionThroughTheDomainLinkCannotConfirmIt(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->signInByDomain()->session->record ?? self::fail('The member did not sign in.');
        $refused = $this->confirmAs($this->callerHolding($session));

        self::assertSame(FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED, $refused->reason);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN->value, DB::table('sso_links')->value('provenance'));
    }

    /**
     * Rows of `[isolation level, sign-in]`: each session the person holds apart
     * from every provider, signed in by the test given, at each isolation
     * level.
     *
     * @return iterable<string, array{0: ?string, 1: \Closure(self): (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)}>
     */
    public static function provideIndependentSessions(): iterable
    {
        foreach (self::provideEveryIsolationLevel() as $name => [$level]) {

            yield 'a password session, ' . $name => [$level, static fn (self $test): EloquentSession&Model => $test->signIn($test->member())->record];

            yield 'a passkey session, ' . $name => [$level, static fn (self $test): EloquentSession&Model => $test->signInWithPasskey()];
        }
    }

    /**
     * Once the person holds a session signed in with a password or a passkey,
     * the same link is confirmed through it at every isolation level, judged
     * inside SSO's transaction in its judgement and its admission, and loses
     * its verified domain provenance.
     *
     * @param  ?string  $level
     * @param  \Closure(self): (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)  $signIn
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIndependentSessions')]
    public function testASessionThePersonHoldsApartConfirmsTheLink(?string $level, \Closure $signIn): void
    {
        self::runAtIsolationLevel($level);

        $this->signInByDomain();

        $confirmed = $this->confirmAs($this->callerHolding($signIn($this)));

        self::assertTrue($confirmed->isRedeemed(), sprintf('The link was not confirmed: [%s].', $confirmed->reason->value ?? $confirmed->status->value));
        self::assertNotSame(LinkOrigin::VERIFIED_DOMAIN->value, DB::table('sso_links')->value('provenance'));
    }

    /**
     * A session the application started for its own recovery confirms only
     * under a method it names at `iam.sso.recovery_methods`; under any other
     * method, or with none named, it is `dependent`.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARecoverySessionConfirmsOnlyUnderAMethodTheApplicationNames(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->startUnder(self::RECOVERY);
        $caller  = $this->callerHolding($session);

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $this->judgeInTransaction($caller));

        Config::set(LinkConfirmationAdapter::RECOVERY_METHODS, ['support_reset', self::RECOVERY]);

        self::assertSame(LinkConfirmationVerdict::INDEPENDENT, $this->judgeInTransaction($caller));

        Config::set(LinkConfirmationAdapter::RECOVERY_METHODS, self::RECOVERY);

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $this->judgeInTransaction($caller));

        Config::set(LinkConfirmationAdapter::RECOVERY_METHODS, [self::RECOVERY]);

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $this->judgeInTransaction($this->callerHolding($this->startUnder('support_reset'))));
    }

    /**
     * A setting that is not a list of method names names no recovery at all,
     * even where one of its values is the method: a keyed array, and a list
     * holding anything but strings, are refused whole.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMalformedRecoverySettingNamesNoRecovery(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $caller = $this->callerHolding($this->startUnder(self::RECOVERY));

        Config::set(LinkConfirmationAdapter::RECOVERY_METHODS, ['support' => self::RECOVERY]);

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $this->judgeInTransaction($caller));

        Config::set(LinkConfirmationAdapter::RECOVERY_METHODS, [self::RECOVERY, 1]);

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $this->judgeInTransaction($caller));

        Config::set(LinkConfirmationAdapter::RECOVERY_METHODS, [1 => self::RECOVERY]);

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $this->judgeInTransaction($caller));

        Config::set(LinkConfirmationAdapter::RECOVERY_METHODS, [self::RECOVERY]);

        self::assertSame(LinkConfirmationVerdict::INDEPENDENT, $this->judgeInTransaction($caller));
    }

    /**
     * A recovery method named does not make a password session's channel, or
     * any other, stand for it: a session the domain link established is
     * `dependent` whatever the application names.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARecoveryMethodNamedNeverCountsAProvidersSession(?string $level): void
    {
        self::runAtIsolationLevel($level);

        Config::set(LinkConfirmationAdapter::RECOVERY_METHODS, ['external_provider', 'password']);

        $session = $this->signInByDomain()->session->record ?? self::fail('The member did not sign in.');

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $this->judgeInTransaction($this->callerHolding($session)));
    }

    /**
     * A password session whose freshness was renewed through a provider (a
     * counting `external_reauthentication` proof) is `dependent`.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testASessionRenewedThroughAProviderIsDependent(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->signIn($this->member())->record;
        $caller  = $this->callerHolding($session);

        self::assertSame(LinkConfirmationVerdict::INDEPENDENT, $this->judgeInTransaction($caller));

        // laravel-authentication refuses such a renewal on a password session,
        // so the proof is written as its own writer would write one
        ProofWriter::record($session, self::GUARD, new NewProof(
            ProofKind::EXTERNAL_REAUTHENTICATION,
            ProofPurpose::REAUTHENTICATE,
            'external_provider',
            new Channel(ChannelKind::EXTERNAL_PROVIDER, $this->connectionId),
            null,
            new ObservedProperties,
            null,
            [],
            CarbonImmutable::now()->startOfSecond(),
        ));

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $this->judgeInTransaction($caller));
    }

    /**
     * Rows of `[isolation level, caller]`: each caller of whom nothing the
     * person holds apart is judged, at each isolation level.
     *
     * @return iterable<string, array{0: ?string, 1: \Closure(self): ?\SineMacula\Laravel\Authentication\Callers\Caller}>
     */
    public static function provideDependentCallers(): iterable
    {
        foreach (self::provideEveryIsolationLevel() as $name => [$level]) {
            foreach (self::dependentCallers() as $caller => [$build]) {
                yield $caller . ', ' . $name => [$level, $build];
            }
        }
    }

    /**
     * Each caller of whom nothing the person holds apart is judged is
     * `dependent`, however the person's own session signed in.
     *
     * @param  ?string  $level
     * @param  \Closure(self): ?\SineMacula\Laravel\Authentication\Callers\Caller  $caller
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDependentCallers')]
    public function testACallerHoldingNothingOfThePersonsOwnIsDependent(?string $level, \Closure $caller): void
    {
        self::runAtIsolationLevel($level);

        $this->passwordSession = $this->signIn($this->member())->record;

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $this->judgeInTransaction($caller($this)));
    }

    /**
     * Outside a transaction no guard can hold the answer true until a redeemer
     * commits, so a password session is `dependent` there, and nothing is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOutsideATransactionEveryoneIsDependent(): void
    {
        $caller     = $this->callerHolding($this->signIn($this->member())->record);
        $connection = $this->ssoConnection();
        $reads      = 0;

        DB::listen(static function () use (&$reads): void {
            $reads++;
        });

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $this->judgeAs($caller, $connection));
        self::assertSame(0, $reads);
    }

    /**
     * Inside a transaction the session's row is locked until it ends, the guard
     * every writer of the session takes, so the answer holds until the redeemer
     * commits.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testTheSessionsRowIsLockedUntilTheTransactionEnds(string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->signIn($this->member())->record;
        $caller  = $this->callerHolding($session);

        DB::transaction(function () use ($caller, $session): void {
            self::assertSame(LinkConfirmationVerdict::INDEPENDENT, $this->judgeAs($caller));
            self::assertTrue($this->isLockedElsewhere($session));
        });

        self::assertFalse($this->isLockedElsewhere($session));
    }

    /**
     * A session revoked on another connection after the caller's transaction
     * read is `dependent` inside it: the proofs are read current, never from
     * the transaction's snapshot (and at PostgreSQL's REPEATABLE READ the lock
     * fails to serialise instead, for the transaction to be retried).
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASessionRevokedSinceTheTransactionReadIsDependent(string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->signIn($this->member())->record;
        $caller  = $this->callerHolding($session);

        $revoke = fn (): bool => $this->sessions()->revokeSession(Person::query()->findOrFail($this->member()->getKey()), $session->getKey(), RevocationReason::REVOKED);
        $answer = $this->askedAfter($level, fn () => $this->elsewhere($revoke), fn (): LinkConfirmationVerdict => $this->judgeAs($caller));

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $answer);
    }

    /**
     * The tests' member of the tenant.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    public function member(): Person
    {
        return $this->person ?? self::fail('The member is not arranged.');
    }

    /**
     * The member's password session the test signed in.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    public function passwordSession(): EloquentSession&Model
    {
        return $this->passwordSession ?? self::fail('The member holds no password session.');
    }

    /**
     * The person, the member unless another is given, as the caller of a
     * request on the guard, its access credential holding the session.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  ?\Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Authentication\Callers\Caller
     */
    public function callerHolding(EloquentSession&Model $session, ?Person $person = null): Caller
    {
        return new Caller(self::GUARD, CallerCredential::ACCESS, $person ?? $this->member(), null, null, $session);
    }

    /**
     * Sign the member in with the passkey registered for them now, and return
     * the session.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    public function signInWithPasskey(): EloquentSession&Model
    {
        $this->registerPasskey($this->member());

        $options = $this->passkeys()->signInOptions(self::client());
        $input   = ['challenge' => $options->challengeId, 'credential' => $this->authenticator()->get($options->options)];
        $result  = $this->sessions()->signIn('passkey', $input, new SignInContext(self::client()));

        return $result->session->record ?? self::fail(sprintf('The member did not sign in with a passkey: [%s].', $result->reason->value ?? $result->status->value));
    }

    /**
     * The sign-in methods the guard allows: the password, a passkey, sign-in
     * through an external provider, and the two the application's own
     * verifications start sessions under.
     *
     * @return list<string>
     */
    #[\Override]
    protected function signInMethods(): array
    {
        return ['password', 'passkey', 'external_provider', self::RECOVERY, 'support_reset'];
    }

    /**
     * Each caller of whom nothing the person holds apart is judged, built by
     * the test given once the person holds a password session
     * (`passwordSession()`), keyed by what it is.
     *
     * @return iterable<string, array{0: \Closure(self): ?\SineMacula\Laravel\Authentication\Callers\Caller}>
     */
    private static function dependentCallers(): iterable
    {
        yield 'no caller handed in' => [static fn (): ?Caller => null];

        yield 'a caller with no session' => [static fn (self $test): Caller => new Caller(self::GUARD, CallerCredential::ACCESS, $test->member(), null, null, null)];

        yield 'a refresh credential' => [
            static fn (self $test): Caller => new Caller(self::GUARD, CallerCredential::REFRESH, $test->member(), null, null, $test->passwordSession()),
        ];

        yield 'another person holding the session' => [
            static fn (self $test): Caller => new Caller(self::GUARD, CallerCredential::ACCESS, $test->createPerson(), null, null, $test->passwordSession()),
        ];

        yield 'another person with a password session of their own' => [
            static fn (self $test): Caller => $test->callerHolding($test->signIn($other = $test->createPerson())->record, $other),
        ];

        yield 'a revoked session' => [static function (self $test): Caller {
            $session = $test->passwordSession();

            $test->sessions()->revokeSession($test->member(), $session->getKey(), RevocationReason::REVOKED);

            return $test->callerHolding($session);
        }];
    }

    /**
     * Start a session for the member as something outside the guard verified
     * them, under the method given.
     *
     * @param  string  $method
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function startUnder(string $method): EloquentSession&Model
    {
        $result = $this->sessions()->start($this->member(), null, $method, new SignInContext(self::client()));

        return $result->session->record ?? self::fail(sprintf('The session was not started: [%s].', $result->reason->value ?? $result->status->value));
    }

    /**
     * Redeem a `link` of the member to the subject their domain link holds,
     * through this package, as the caller.
     *
     * @param  \SineMacula\Laravel\Authentication\Callers\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function confirmAs(Caller $caller): RedemptionResult
    {
        $handoff = $this->handoff(Purpose::LINK, $this->member(), tailor: self::byDomain());

        return Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $caller);
    }

    /**
     * The tests' connection, as SSO hands it to the contract.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function ssoConnection(): Connection
    {
        return Connection::query()->findOrFail($this->connectionId);
    }

    /**
     * Ask the adapter about the member, inside a transaction on the storage
     * connection, with the caller handed in, if any.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Callers\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     *
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    private function judgeInTransaction(?Caller $caller): LinkConfirmationVerdict
    {
        return DB::transaction(fn (): LinkConfirmationVerdict => $this->judgeAs($caller));
    }

    /**
     * Ask the adapter about the member, with the caller handed in, if any, as a
     * `link` redemption hands it in.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Callers\Caller  $caller
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     *
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    private function judgeAs(?Caller $caller, ?Connection $connection = null): LinkConfirmationVerdict
    {
        $app      = $this->app ?? self::fail('The application has not booted.');
        $callers  = $app->make(LinkCallers::class);
        $adapter  = $this->resolved(LinkConfirmation::class);
        $identity = self::referenceOf($this->member());

        if ($caller !== null) {
            $callers->open($caller, false);
        }

        self::assertInstanceOf(LinkConfirmationAdapter::class, $adapter);

        try {
            return $adapter->judge($identity, $connection ?? $this->ssoConnection(), []);
        } finally {
            if ($caller !== null) {
                $callers->close();
            }
        }
    }

    /**
     * What the container resolves the abstract to.
     *
     * @param  string  $abstract
     * @return mixed
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }
}
