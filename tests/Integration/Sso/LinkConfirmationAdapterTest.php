<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\External\ProviderContext;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as ProofPurpose;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\LinkConfirmationAdapter;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\Caller as SsoCaller;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Testing\Seams\Concerns\LinkConfirmationContract;
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
 * Integration tests for SSO's link confirmation adapter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkConfirmationAdapter::class)]
#[CoversClass(SsoSeams::class)]
final class LinkConfirmationAdapterTest extends TestCase
{
    use ChangesSessionsElsewhere, FindsLockedSessions, LinkConfirmationContract, LinksByVerifiedDomain, MigratesSso,
        RegistersPasskeys, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The sign-in method of the application's own recovery in these tests. */
    private const string RECOVERY = 'account_recovery';

    /** @var ?\Tests\Fixtures\Models\Person The member of the tenant the domain links. */
    private ?Person $person = null;

    /** @var (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null The member's password session, once a test signs them in. */
    private (EloquentSession&Model)|null $passwordSession = null;

    /** @var (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null The member's session through the domain link, once signed in. */
    private (EloquentSession&Model)|null $domainSession = null;

    /**
     * Arrange SSO with a verified domain and a member holding its email.
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
     * The adapter is the link confirmation SSO resolves.
     *
     * @return void
     */
    public function testTheAdapterIsSsosLinkConfirmation(): void
    {
        self::assertInstanceOf(LinkConfirmationAdapter::class, $this->resolved(LinkConfirmation::class));
    }

    /**
     * A session through the domain link cannot confirm that link.
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
        $refused = $this->confirmAs($session);

        self::assertSame(FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED, $refused->reason);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN->value, DB::table('sso_links')->value('provenance'));
    }

    /**
     * Rows of `[isolation level, sign-in]`: each independent session.
     *
     * @return iterable<string, array{0: ?string, 1: \Closure(self): (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)}>
     */
    public static function provideIndependentSessions(): iterable
    {
        foreach (self::provideEveryIsolationLevel() as $name => [$level]) {

            yield 'a password session, ' . $name => [$level, static fn (self $test): EloquentSession&Model => $test->signIn($test->member())->record];

            yield 'a passkey session, ' . $name => [$level, static fn (self $test): EloquentSession&Model => $test->signInWithPasskey()];

            yield 'a recovery session, ' . $name => [$level, static fn (self $test): EloquentSession&Model => $test->startOn(ChannelKind::RECOVERY)];
        }
    }

    /**
     * A password, passkey or recovery session confirms the link.
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

        $confirmed = $this->confirmAs($signIn($this));

        self::assertTrue($confirmed->isRedeemed(), sprintf('The link was not confirmed: [%s].', $confirmed->reason->value ?? $confirmed->status->value));
        self::assertNotSame(LinkOrigin::VERIFIED_DOMAIN->value, DB::table('sso_links')->value('provenance'));
    }

    /**
     * Only a session started on the `recovery` channel is independent.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testOnlyAStartedSessionOnTheRecoveryChannelIsIndependent(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $recovery = $this->callerHolding($this->startOn(ChannelKind::RECOVERY));
        $unknown  = $this->callerHolding($this->startOn(ChannelKind::UNKNOWN));

        self::assertSame(LinkConfirmationVerdict::INDEPENDENT, $this->judgeInTransaction($recovery));
        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $this->judgeInTransaction($unknown));
    }

    /**
     * A session renewed through a provider is `dependent`.
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

        // laravel-authentication refuses this renewal on a password session
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
     * Rows of `[isolation level, link provenance, verdict]`.
     *
     * @return iterable<string, array{0: ?string, 1: ?\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin, 2: \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict}>
     */
    public static function provideRecordedLinks(): iterable
    {
        foreach (self::provideEveryIsolationLevel() as $name => [$level]) {

            yield 'a verified domain link, ' . $name => [$level, LinkOrigin::VERIFIED_DOMAIN, LinkConfirmationVerdict::DEPENDENT];

            yield 'a link the person made, ' . $name => [$level, LinkOrigin::LINK_PURPOSE, LinkConfirmationVerdict::INDEPENDENT];

            yield 'no provider context, ' . $name => [$level, null, LinkConfirmationVerdict::INDEPENDENT];
        }
    }

    /**
     * A session recording a verified domain link is `dependent`.
     *
     * @param  ?string  $level
     * @param  ?\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict  $verdict
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRecordedLinks')]
    public function testASessionRecordingAVerifiedDomainLinkIsDependent(?string $level, ?LinkOrigin $origin, LinkConfirmationVerdict $verdict): void
    {
        self::runAtIsolationLevel($level);

        $domain  = $this->signInByDomain()->session->record ?? self::fail('The member did not sign in.');
        $through = $this->sessions()->provenance($domain)   ?? self::fail('The domain session recorded no provenance.');
        $stored  = $through->providerContext?->toArray()    ?? self::fail('The domain session recorded no provider context.');
        $session = $this->signIn($this->member())->record;
        $caller  = $this->callerHolding($session);

        self::assertSame(LinkOrigin::VERIFIED_DOMAIN->value, $stored['link_provenance'] ?? null);
        self::assertSame(LinkConfirmationVerdict::INDEPENDENT, $this->judgeInTransaction($caller));

        // laravel-authentication records provenance only for provider sessions
        $context = $origin === null ? null : new ProviderContext([...$stored, 'link_provenance' => $origin->value]);

        ProofWriter::provenance($session, new Provenance($through->connectionId, $through->tenantId, linkId: $through->linkId, providerContext: $context));

        self::assertSame($verdict, $this->judgeInTransaction($caller));
    }

    /**
     * Rows of `[isolation level, caller]`: each caller judged dependent.
     *
     * @return iterable<string, array{0: ?string, 1: \Closure(self): \SineMacula\Laravel\Sso\Identities\Caller}>
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
     * A caller holding nothing of the person's own is `dependent`.
     *
     * @param  ?string  $level
     * @param  \Closure(self): \SineMacula\Laravel\Sso\Identities\Caller  $caller
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
     * Outside a transaction every session is `dependent` without a read.
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
     * The session's row is locked until the transaction ends.
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
     * A session revoked since the transaction read is `dependent`.
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

        $revoke = fn (): bool => $this->sessions()->revokeSession(Person::query()->whereKey($this->member()->getKey())->sole(), $session->getKey(), RevocationReason::REVOKED);
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
     * The member as SSO's caller, naming the session given.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    public function callerHolding(EloquentSession&Model $session): SsoCaller
    {
        return new SsoCaller(self::referenceOf($this->member()), self::keyOf($session));
    }

    /**
     * Sign the member in with a passkey, and return the session.
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
     * Start a session for the member from a first factor on the channel.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind  $channel
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    public function startOn(ChannelKind $channel): EloquentSession&Model
    {
        $factor = new FirstFactor($this->member(), new Channel($channel));
        $result = $this->sessions()->start($factor, null, self::RECOVERY, new SignInContext(self::client()));

        return $result->session->record ?? self::fail(sprintf('The session was not started: [%s].', $result->reason->value ?? $result->status->value));
    }

    /**
     * The adapter under SSO's link confirmation contract kit.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\LinkConfirmation
     */
    #[\Override]
    protected function linkConfirmation(): LinkConfirmation
    {
        $adapter = $this->resolved(LinkConfirmation::class);

        return $adapter instanceof LinkConfirmationAdapter ? $adapter : self::fail('The adapter is not bound.');
    }

    /**
     * The tests' connection, which holds the domain.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SsoConnection
     */
    #[\Override]
    protected function confirmationConnection(): SsoConnection
    {
        return $this->ssoConnection();
    }

    /**
     * The member on a password session.
     *
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function independentCaller(): SsoCaller
    {
        return $this->callerHolding($this->signIn($this->member())->record);
    }

    /**
     * The member on the session the domain link signed in.
     *
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function dependentCaller(): SsoCaller
    {
        return $this->callerHolding($this->domainSession());
    }

    /**
     * Another person's password session.
     *
     * @return string
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function otherIdentitysSessionId(): string
    {
        return self::keyOf($this->signIn($this->createPerson())->record);
    }

    /**
     * The domain links the member holds, once the domain signed them in.
     *
     * @return list<string>
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function domainLinkIds(): array
    {
        $this->domainSession();

        $ids = DB::table('sso_links')
            ->where('identity_id', self::keyOf($this->member()))
            ->where('provenance', LinkOrigin::VERIFIED_DOMAIN->value)
            ->pluck('id')
            ->map(static fn (mixed $id): string => is_string($id) ? $id : self::fail('A link has no id.'))
            ->all();

        return $ids !== [] ? array_values($ids) : self::fail('The domain linked nobody.');
    }

    /**
     * Bind the application's memberships before the seams are bound.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $app->bind(Memberships::class, FakeMemberships::class);
    }

    /**
     * The sign-in methods the guard allows.
     *
     * @return list<string>
     */
    #[\Override]
    protected function signInMethods(): array
    {
        return ['password', 'passkey', 'external_provider', self::RECOVERY];
    }

    /**
     * Each dependent caller, keyed by what it is.
     *
     * @return iterable<string, array{0: \Closure(self): \SineMacula\Laravel\Sso\Identities\Caller}>
     */
    private static function dependentCallers(): iterable
    {
        yield 'a session that does not exist' => [static fn (self $test): SsoCaller => new SsoCaller(self::referenceOf($test->member()), 'no-such-session')];

        yield 'a session of a guard that holds no sessions' => [static function (self $test): SsoCaller {
            $session = $test->passwordSession();

            $session->newQuery()->whereKey($session->getKey())->update([$session->getGuardName() => 'web']);

            return $test->callerHolding($session);
        }];

        yield 'a revoked session' => [static function (self $test): SsoCaller {
            $session = $test->passwordSession();

            $test->sessions()->revokeSession($test->member(), $session->getKey(), RevocationReason::REVOKED);

            return $test->callerHolding($session);
        }];
    }

    /**
     * The member's session through the domain link, signed in once.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function domainSession(): EloquentSession&Model
    {
        return $this->domainSession ??= $this->signInByDomain()->session->record ?? self::fail('The member did not sign in.');
    }

    /**
     * Redeem a `link` for the member as the caller holding the session.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function confirmAs(EloquentSession&Model $session): RedemptionResult
    {
        $handoff = $this->handoff(Purpose::LINK, $this->member(), tailor: self::byDomain());
        $caller  = new Caller(self::GUARD, CallerCredential::ACCESS, $this->member(), null, null, $session);

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
     * Ask the adapter about the caller inside a storage transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     *
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    private function judgeInTransaction(SsoCaller $caller): LinkConfirmationVerdict
    {
        return DB::transaction(fn (): LinkConfirmationVerdict => $this->judgeAs($caller));
    }

    /**
     * Ask the adapter about the caller, as a `link` redemption hands it over.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     *
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    private function judgeAs(SsoCaller $caller, ?Connection $connection = null): LinkConfirmationVerdict
    {
        $adapter = $this->resolved(LinkConfirmation::class);

        self::assertInstanceOf(LinkConfirmationAdapter::class, $adapter);

        return $adapter->judge($caller, $connection ?? $this->ssoConnection(), []);
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
