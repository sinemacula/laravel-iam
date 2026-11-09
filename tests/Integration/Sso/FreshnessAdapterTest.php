<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\CallerScope;
use SineMacula\Laravel\Iam\Sso\FreshnessAdapter;
use SineMacula\Laravel\Iam\Sso\LinkCallers;
use SineMacula\Laravel\Iam\Sso\LinkRedemption;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RecordsFreshnessReadModes;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\Handoff;
use Tests\TestCase;

/**
 * Integration tests for SSO's freshness contract over
 * `laravel-authentication`'s freshness policy: SSO's maximum age is the
 * caller's requirement, met by a proof of any kind made within it, and the
 * stricter of it and the application's own requirement for the operation
 * applies; only a caller handed in as a plain value (a `link` redemption's, or
 * one the application hands in through `CallerScope`) is judged, on the session
 * its access credential holds while that session is its own, and with none
 * handed in, or one holding no session of its own, the answer is `stale`,
 * however fresh the session the request is served with; the policy is asked
 * plainly, inside SSO's transactions too, so no session row is locked under
 * SSO's locks, and a caller handed in while a transaction was already open is
 * `stale` while it is; and a `link` redeemed through this package is created
 * for a caller signed in recently enough, and refused as `freshness_required`
 * otherwise, or inside the caller's own transaction.
 *
 * The scenarios that judge a session inside SSO's transaction run at the
 * connection's own level on every engine, then at READ COMMITTED and REPEATABLE
 * READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessAdapter::class)]
#[CoversClass(CallerScope::class)]
#[CoversClass(LinkCallers::class)]
#[CoversClass(LinkRedemption::class)]
final class FreshnessAdapterTest extends TestCase
{
    use MigratesSso, RecordsFreshnessReadModes, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var int The maximum age SSO asks of every operation by default, in seconds. */
    private const int MAX_AGE = 300;

    /**
     * Arrange SSO, with this package's freshness adapter in place of the
     * stand-in the flows bind.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->app?->forgetInstance(Freshness::class);
    }

    /**
     * The adapter is the freshness contract SSO resolves.
     *
     * @return void
     */
    public function testTheAdapterIsSsosFreshness(): void
    {
        self::assertInstanceOf(FreshnessAdapter::class, $this->resolved(Freshness::class));
    }

    /**
     * A session signed in within SSO's maximum age is fresh for every one of
     * SSO's operations, and stale once it is older.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSsosMaximumAgeIsTheCallersRequirement(): void
    {
        $this->freezeSecond();

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        foreach (FreshnessOperation::cases() as $operation) {
            self::assertSame(FreshnessOutcome::FRESH, $this->checkAs($person, $operation), $operation->value);
        }

        $this->travel(self::MAX_AGE - 1)->seconds();

        self::assertSame(FreshnessOutcome::FRESH, $this->checkAs($person, FreshnessOperation::LINK_REMOVE));

        $this->travel(2)->seconds();

        self::assertSame(FreshnessOutcome::STALE, $this->checkAs($person, FreshnessOperation::LINK_REMOVE));
        self::assertSame(FreshnessOutcome::FRESH, $this->checkAs($person, FreshnessOperation::LINK_REMOVE, self::MAX_AGE * 2));
    }

    /**
     * SSO's gate asks with the maximum age its configuration gives the
     * operation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSsosGateAsksWithItsConfiguredMaximumAge(): void
    {
        Config::set('sso.freshness.max_age_seconds.link_remove', 60);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $this->travel(61)->seconds();

        $gate = $this->app?->make(FreshnessGate::class) ?? self::fail('The application has not booted.');

        $caller = $this->requestCallerOf($person);

        self::assertSame(FreshnessOutcome::STALE, Iam::callers()->run($caller, static fn (): FreshnessOutcome => $gate->check(FreshnessOperation::LINK_REMOVE)));
        self::assertSame(FreshnessOutcome::FRESH, Iam::callers()->run($caller, static fn (): FreshnessOutcome => $gate->check(FreshnessOperation::LINK_CREATE)));
    }

    /**
     * The application's own requirement for the operation applies where it is
     * stricter than SSO's: a shorter age makes the session stale sooner, and
     * proof kinds the sign-in's first factor is not among make it stale at
     * once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationsStricterRequirementApplies(): void
    {
        Config::set('authentication.freshness', [
            FreshnessOperation::LINK_REMOVE->value => ['max_age_seconds' => 60, 'proofs' => ['first_factor', 'first_factor_reauthentication']],
            FreshnessOperation::KEYS_ROTATE->value => ['max_age_seconds' => 3600, 'proofs' => ['additional_factor']],
            FreshnessOperation::LINK_CREATE->value => ['max_age_seconds' => 3600, 'proofs' => ['first_factor']],
        ]);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        self::assertSame(FreshnessOutcome::STALE, $this->checkAs($person, FreshnessOperation::KEYS_ROTATE));

        $this->travel(61)->seconds();

        self::assertSame(FreshnessOutcome::STALE, $this->checkAs($person, FreshnessOperation::LINK_REMOVE));
        self::assertSame(FreshnessOutcome::FRESH, $this->checkAs($person, FreshnessOperation::LINK_CREATE));
    }

    /**
     * With no caller (no one signed in, as in a queued job or a console
     * command) the answer is stale.
     *
     * @return void
     */
    public function testNoCallerIsStale(): void
    {
        self::assertSame(FreshnessOutcome::STALE, $this->adapter()->check(FreshnessOperation::CONNECTION_TRUST, self::MAX_AGE));
    }

    /**
     * Without a caller handed in, the answer is stale however fresh the session
     * the request is served with: neither the default guard nor whoever it
     * serves is ever taken as the caller, and the policy is not asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignedInSessionIsStaleWithoutACallerHandedIn(): void
    {
        $this->signInAndActOnSession($this->createPerson());

        $recorder = $this->recordReadModes();

        self::assertSame(FreshnessOutcome::STALE, $this->adapter()->check(FreshnessOperation::CONNECTION_TRUST, self::MAX_AGE));
        self::assertSame([], $recorder->modes);
    }

    /**
     * The caller scope hands the caller in for its work alone: the work's
     * answer is returned, and once it ends, however it ends, no caller is
     * handed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallerScopeHandsTheCallerInForItsWorkAlone(): void
    {
        $person  = $this->createPerson();
        $callers = $this->app?->make(LinkCallers::class) ?? self::fail('The application has not booted.');

        $this->signInAndActOnSession($person);

        self::assertSame(FreshnessOutcome::FRESH, $this->checkAs($person, FreshnessOperation::CONNECTION_TRUST));
        self::assertNull($callers->current());

        $failure = new \RuntimeException('The work failed.');
        $caught  = null;

        try {
            Iam::callers()->run($this->requestCallerOf($person), static fn (): never => throw $failure);
        } catch (\RuntimeException $exception) {
            $caught = $exception;
        }

        self::assertSame($failure, $caught);
        self::assertNull($callers->current());
        self::assertSame(FreshnessOutcome::STALE, $this->adapter()->check(FreshnessOperation::CONNECTION_TRUST, self::MAX_AGE));
    }

    /**
     * A caller handed in for an application that is no session guard throws
     * before the work runs, and nothing is handed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerOnAGuardThatHoldsNoSessionsThrowsBeforeTheWorkRuns(): void
    {
        Config::set('auth.guards.web', ['driver' => 'session', 'provider' => 'people']);

        $ran = false;

        try {
            Iam::callers()->run(new Caller('web', CallerCredential::ACCESS, $this->createPerson(), null, null, null), static function () use (&$ran): void {
                $ran = true;
            });
            self::fail('A guard that holds no sessions was accepted.');
        } catch (UnresolvedReferenceException) {
            self::assertFalse($ran);
        }

        self::assertNull($this->app?->make(LinkCallers::class)->current());
    }

    /**
     * A caller whose identity SSO cannot name (one that is no model) throws
     * before the work runs, and nothing is handed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerWhoseIdentityCannotBeNamedThrowsBeforeTheWorkRuns(): void
    {
        $ran = false;

        try {
            Iam::callers()->run(new Caller(self::GUARD, CallerCredential::ACCESS, self::createStub(Identity::class), null, null, null), static function () use (&$ran): void {
                $ran = true;
            });
            self::fail('An identity SSO cannot name was accepted.');
        } catch (UnresolvedReferenceException) {
            self::assertFalse($ran);
        }

        self::assertNull($this->app?->make(LinkCallers::class)->current());
    }

    /**
     * While a `link` redemption runs, the session the caller holds is judged
     * only while it is the caller's own: fresh for the person whose session it
     * is, stale for a caller handed in holding another person's, however fresh
     * that session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkCallerIsJudgedOnItsOwnSessionAlone(): void
    {
        $caller  = $this->createPerson();
        $other   = $this->createPerson();
        $callers = $this->app?->make(LinkCallers::class) ?? self::fail('The application has not booted.');

        $this->signInAndActOnSession($caller);

        $callers->open($this->requestCallerOf($caller), false);

        self::assertSame(FreshnessOutcome::FRESH, $this->adapter()->check(FreshnessOperation::LINK_CREATE, self::MAX_AGE));

        $callers->close();
        $callers->open($this->requestCallerOf($other), false);

        self::assertSame(FreshnessOutcome::STALE, $this->adapter()->check(FreshnessOperation::LINK_CREATE, self::MAX_AGE));

        $callers->close();
    }

    /**
     * Only the session an access credential holds is judged: a caller read from
     * a refresh credential is stale, however fresh the session it holds, and a
     * caller holding its own session is judged without the guard being asked
     * whom it serves.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheSessionAnAccessCredentialHoldsIsJudged(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $callers = $this->app?->make(LinkCallers::class) ?? self::fail('The application has not booted.');

        $callers->open(new Caller(self::GUARD, CallerCredential::REFRESH, $person, null, null, $session), false);

        self::assertSame(FreshnessOutcome::STALE, $this->adapter()->check(FreshnessOperation::LINK_CREATE, self::MAX_AGE));

        $callers->close();

        $this->signInAndActOnSession($this->createPerson());

        $callers->open(new Caller(self::GUARD, CallerCredential::ACCESS, $person, null, null, $session), false);

        self::assertSame(FreshnessOutcome::FRESH, $this->adapter()->check(FreshnessOperation::LINK_CREATE, self::MAX_AGE));

        $callers->close();
    }

    /**
     * A `link` caller holding no session is stale.
     *
     * @return void
     */
    public function testALinkCallerWithNoSessionIsStale(): void
    {
        $callers = $this->app?->make(LinkCallers::class) ?? self::fail('The application has not booted.');

        $callers->open($this->requestCallerOf($this->createPerson()), false);

        self::assertSame(FreshnessOutcome::STALE, $this->adapter()->check(FreshnessOperation::LINK_CREATE, self::MAX_AGE));

        $callers->close();
    }

    /**
     * Inside a transaction on the storage connection opened after the caller
     * was handed in, as SSO opens its own, the policy is still asked plainly,
     * by this adapter, for the operation SSO named: no session row is locked
     * under SSO's locks.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testThePolicyIsAskedPlainlyInsideSsosTransaction(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $recorder = $this->recordReadModes();
        $check    = fn (): FreshnessOutcome => $this->adapter()->check(FreshnessOperation::ENFORCEMENT_UPDATE, self::MAX_AGE);
        $answer   = Iam::callers()->run($this->requestCallerOf($person), static fn (): FreshnessOutcome => DB::transaction($check));

        self::assertSame(FreshnessOutcome::FRESH, $answer);
        self::assertAskedOnlyIn($recorder, false);
        self::assertAskedOnlyBy($recorder, FreshnessAdapter::class, FreshnessOperation::ENFORCEMENT_UPDATE->value);
    }

    /**
     * A caller handed in while a transaction is already open is stale while a
     * transaction is open, without the policy being asked, since that
     * transaction's snapshot may be older than the call; once no transaction is
     * open, it is judged.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testACallerHandedInInsideATransactionIsStaleWhileOneIsOpen(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $recorder = $this->recordReadModes();
        $answer   = DB::transaction(fn (): FreshnessOutcome => $this->checkAs($person, FreshnessOperation::LINK_CREATE));

        self::assertSame(FreshnessOutcome::STALE, $answer);
        self::assertSame([], $recorder->modes);

        $callers = $this->app?->make(LinkCallers::class) ?? self::fail('The application has not booted.');

        $callers->open($this->requestCallerOf($person), true);

        self::assertSame(FreshnessOutcome::STALE, DB::transaction(fn (): FreshnessOutcome => $this->adapter()->check(FreshnessOperation::LINK_CREATE, self::MAX_AGE)));
        self::assertSame(FreshnessOutcome::FRESH, $this->adapter()->check(FreshnessOperation::LINK_CREATE, self::MAX_AGE));

        $callers->close();
    }

    /**
     * A `link` redeemed through this package for a caller signed in within
     * SSO's maximum age is created, freshness asked plainly under SSO's locks
     * for the caller, and the record of the caller is closed once SSO has
     * answered.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testALinkIsRedeemedForACallerFreshEnough(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $handoff  = $this->linkHandoff($person);
        $recorder = $this->recordReadModes();
        $linked   = Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($person));

        self::assertTrue($linked->isRedeemed(), sprintf('The person was not linked: [%s].', $linked->reason->value ?? $linked->status->value));
        self::assertAskedOnlyIn($recorder, false);
        self::assertAskedOnlyBy($recorder, FreshnessAdapter::class, FreshnessOperation::LINK_CREATE->value);
        self::assertSame(1, DB::table('sso_links')->count());
        self::assertNull($this->app?->make(LinkCallers::class)->current());
    }

    /**
     * A `link` whose caller signed in longer ago than SSO's maximum age when it
     * is redeemed is refused as `freshness_required` under SSO's locks, and no
     * link is made.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testALinkIsRefusedForACallerNoLongerFresh(?string $level): void
    {
        self::runAtIsolationLevel($level);

        Config::set('sso.freshness.max_age_seconds.link_create', 5);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $handoff = $this->linkHandoff($person);

        $this->travel(6)->seconds();

        $refused = Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($person));

        self::assertFalse($refused->isRedeemed());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $refused->reason);
        self::assertSame(0, DB::table('sso_links')->count());
        self::assertNull($this->app?->make(LinkCallers::class)->current());
    }

    /**
     * A `link` started for one person and redeemed by a caller holding another
     * person's session is refused for freshness before anything else: only the
     * caller's own session is judged, and the caller holds none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkWhoseCallerHoldsAnotherPersonsSessionIsRefused(): void
    {
        $caller = $this->createPerson();

        $this->signInAndActOnSession($caller);

        $handoff = $this->linkHandoff($caller);

        $this->signInAndActOnSession($this->createPerson());

        $refused = Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($caller));

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $refused->reason);
        self::assertSame(0, DB::table('sso_links')->count());
    }

    /**
     * A `link` redeemed inside the caller's own transaction is refused as
     * `freshness_required`, however recently the caller signed in: that
     * transaction's snapshot may be older than the redemption, and the policy
     * is not asked. No link is made, and the record is closed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkInsideTheCallersTransactionIsRefused(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $handoff  = $this->linkHandoff($person);
        $caller   = $this->requestCallerOf($person);
        $recorder = $this->recordReadModes();
        $refused  = DB::transaction(fn (): RedemptionResult => Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $caller));

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $refused->reason);
        self::assertSame([], $recorder->modes);
        self::assertSame(0, DB::table('sso_links')->count());
        self::assertNull($this->app?->make(LinkCallers::class)->current());
    }

    /**
     * A `link` flow started with no caller handed in is refused for freshness
     * at its start, however recently the person signed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkFlowStartedWithoutACallerHandedInIsRefused(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $gate = $this->app?->make(FreshnessGate::class) ?? self::fail('The application has not booted.');

        $check = static fn (): FreshnessOutcome => $gate->check(FreshnessOperation::LINK_CREATE);

        self::assertSame(FreshnessOutcome::STALE, $check());
        self::assertSame(FreshnessOutcome::FRESH, Iam::callers()->run($this->requestCallerOf($person), $check));
    }

    /**
     * Ask the adapter for the operation with the person handed in as the caller
     * of a request on the guard, holding the session the guard serves.
     *
     * @param  \Tests\Fixtures\Models\Person  $caller
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAge
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     *
     * @throws \Throwable
     */
    private function checkAs(Person $caller, FreshnessOperation $operation, int $maxAge = self::MAX_AGE): FreshnessOutcome
    {
        return Iam::callers()->run($this->requestCallerOf($caller), fn (): FreshnessOutcome => $this->adapter()->check($operation, $maxAge));
    }

    /**
     * Start and complete a `link` flow for the person, handed in as the caller
     * of a request on the guard, as SSO's flow start asks freshness, and answer
     * its handoff.
     *
     * @param  \Tests\Fixtures\Models\Person  $caller
     * @return \Tests\Fixtures\Sso\Handoff
     *
     * @throws \Throwable
     */
    private function linkHandoff(Person $caller): Handoff
    {
        return Iam::callers()->run($this->requestCallerOf($caller), fn (): Handoff => $this->handoff(Purpose::LINK, $caller));
    }

    /**
     * The adapter, as SSO resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Sso\FreshnessAdapter
     */
    private function adapter(): FreshnessAdapter
    {
        $adapter = $this->resolved(Freshness::class);

        return $adapter instanceof FreshnessAdapter ? $adapter : self::fail('The adapter is not bound.');
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
