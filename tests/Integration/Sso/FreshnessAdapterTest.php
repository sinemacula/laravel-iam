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
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\Callers;
use SineMacula\Laravel\Iam\Sso\FreshnessAdapter;
use SineMacula\Laravel\Iam\Sso\LinkRedemption;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\Caller as SsoCaller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
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
 * applies; only the caller SSO hands over is judged, on the session it names
 * while that session is live and its identity's own, and for no caller, or one
 * with no session, the answer is `stale`, however fresh the session the request
 * is served with; the application names its caller as SSO takes it
 * (`Iam::callers()->of()`), with the session its access credential holds while
 * it is its own and no transaction is open; the policy is asked plainly, inside
 * SSO's transactions too, so no session row is locked under SSO's locks; and a
 * `link` redeemed through this package is created for a caller signed in
 * recently enough, and refused as `freshness_required` otherwise, or inside the
 * caller's own transaction.
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
#[CoversClass(Callers::class)]
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
     * operation, for the caller it is given.
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

        $gate   = $this->app?->make(FreshnessGate::class) ?? self::fail('The application has not booted.');
        $caller = $this->namedCallerOf($person);

        self::assertSame(FreshnessOutcome::STALE, $gate->check(FreshnessOperation::LINK_REMOVE, $caller));
        self::assertSame(FreshnessOutcome::FRESH, $gate->check(FreshnessOperation::LINK_CREATE, $caller));
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
     * With no caller (as in a queued job or a console command) the answer is
     * stale.
     *
     * @return void
     */
    public function testNoCallerIsStale(): void
    {
        self::assertSame(FreshnessOutcome::STALE, $this->adapter()->check(FreshnessOperation::CONNECTION_TRUST, self::MAX_AGE, null));
    }

    /**
     * A caller with no session is stale however fresh the session the request
     * is served with: neither the default guard nor whoever it serves is ever
     * taken as the caller's, and the policy is not asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerWithNoSessionIsStale(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $recorder = $this->recordReadModes();

        self::assertSame(FreshnessOutcome::STALE, $this->adapter()->check(FreshnessOperation::CONNECTION_TRUST, self::MAX_AGE, new SsoCaller(self::referenceOf($person))));
        self::assertSame([], $recorder->modes);
    }

    /**
     * The caller is judged on the session it names only while that session is
     * its identity's own and live: another person's session, a key that names
     * no session, and a session since revoked are stale, however fresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerIsJudgedOnItsOwnLiveSessionAlone(): void
    {
        $person  = $this->createPerson();
        $other   = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $check   = fn (SsoCaller $caller): FreshnessOutcome => $this->adapter()->check(FreshnessOperation::LINK_CREATE, self::MAX_AGE, $caller);

        self::assertSame(FreshnessOutcome::FRESH, $check(new SsoCaller(self::referenceOf($person), self::keyOf($session))));
        self::assertSame(FreshnessOutcome::STALE, $check(new SsoCaller(self::referenceOf($other), self::keyOf($session))));
        self::assertSame(FreshnessOutcome::STALE, $check(new SsoCaller(self::referenceOf($person), 'no-such-session')));

        $this->sessions()->revokeSession($person, $session->getKey(), RevocationReason::REVOKED);

        self::assertSame(FreshnessOutcome::STALE, $check(new SsoCaller(self::referenceOf($person), self::keyOf($session))));
    }

    /**
     * A caller whose identity reference names no identity throws, rather than
     * be answered as no caller.
     *
     * @return void
     */
    public function testACallerNamingNoIdentityThrows(): void
    {
        $this->expectException(UnresolvedReferenceException::class);

        $this->adapter()->check(FreshnessOperation::LINK_CREATE, self::MAX_AGE, new SsoCaller(new IdentityReference(Person::class, '404'), 'session'));
    }

    /**
     * A caller is named with the session its access credential holds while it
     * is the caller's own: a caller read from a refresh credential, or holding
     * another person's session, is named with none, and a caller holding its
     * own session is named with it without the guard being asked whom it
     * serves.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheSessionAnAccessCredentialHoldsIsNamed(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $callers = Iam::callers();

        self::assertNull($callers->of(new Caller(self::GUARD, CallerCredential::REFRESH, $person, null, null, $session))->sessionId);
        self::assertNull($callers->of(new Caller(self::GUARD, CallerCredential::ACCESS, $this->createPerson(), null, null, $session))->sessionId);
        self::assertNull($callers->of(new Caller(self::GUARD, CallerCredential::ACCESS, $person, null, null, null))->sessionId);

        $this->signInAndActOnSession($this->createPerson());

        $named = $callers->of(new Caller(self::GUARD, CallerCredential::ACCESS, $person, null, null, $session));

        self::assertTrue($named->identity->is(self::referenceOf($person)));
        self::assertSame(self::keyOf($session), $named->sessionId);
        self::assertSame(FreshnessOutcome::FRESH, $this->adapter()->check(FreshnessOperation::LINK_CREATE, self::MAX_AGE, $named));
    }

    /**
     * A caller on an application that is no session guard cannot be named.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerOnAGuardThatHoldsNoSessionsCannotBeNamed(): void
    {
        Config::set('auth.guards.web', ['driver' => 'session', 'provider' => 'people']);

        $this->expectException(UnresolvedReferenceException::class);

        Iam::callers()->of(new Caller('web', CallerCredential::ACCESS, $this->createPerson(), null, null, null));
    }

    /**
     * A caller whose identity SSO cannot name (one that is no model) cannot be
     * named.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerWhoseIdentityCannotBeNamedCannotBeNamed(): void
    {
        $this->expectException(UnresolvedReferenceException::class);

        Iam::callers()->of(new Caller(self::GUARD, CallerCredential::ACCESS, self::createStub(Identity::class), null, null, null));
    }

    /**
     * Inside a transaction on the storage connection opened after the caller
     * was named, as SSO opens its own, the policy is still asked plainly, by
     * this adapter, for the operation SSO named: no session row is locked under
     * SSO's locks.
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

        $caller   = $this->namedCallerOf($person);
        $recorder = $this->recordReadModes();
        $answer   = DB::transaction(fn (): FreshnessOutcome => $this->adapter()->check(FreshnessOperation::ENFORCEMENT_UPDATE, self::MAX_AGE, $caller));

        self::assertSame(FreshnessOutcome::FRESH, $answer);
        self::assertAskedOnlyIn($recorder, false);
        self::assertAskedOnlyBy($recorder, FreshnessAdapter::class, FreshnessOperation::ENFORCEMENT_UPDATE->value);
    }

    /**
     * A caller named while a transaction is open is named with no session, so
     * it is stale without the policy being asked, since that transaction's
     * snapshot may be older than the call; one named once no transaction is
     * open is judged.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testACallerNamedInsideATransactionCarriesNoSession(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $recorder = $this->recordReadModes();
        $answer   = DB::transaction(fn (): FreshnessOutcome => $this->checkAs($person, FreshnessOperation::LINK_CREATE));

        self::assertSame(FreshnessOutcome::STALE, $answer);
        self::assertSame([], $recorder->modes);
        self::assertSame(FreshnessOutcome::FRESH, $this->checkAs($person, FreshnessOperation::LINK_CREATE));
    }

    /**
     * A `link` redeemed through this package for a caller signed in within
     * SSO's maximum age is created, freshness asked plainly under SSO's locks
     * for the caller.
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
     * transaction's snapshot may be older than the redemption, so the caller is
     * handed to SSO with no session, and the policy is not asked. No link is
     * made.
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
    }

    /**
     * A `link` flow started for a caller with no session is refused for
     * freshness at its start, however recently the person signed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkFlowStartedForACallerWithNoSessionIsRefused(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $gate = $this->app?->make(FreshnessGate::class) ?? self::fail('The application has not booted.');

        self::assertSame(FreshnessOutcome::STALE, $gate->check(FreshnessOperation::LINK_CREATE, new SsoCaller(self::referenceOf($person))));
        self::assertSame(FreshnessOutcome::FRESH, $gate->check(FreshnessOperation::LINK_CREATE, $this->namedCallerOf($person)));
    }

    /**
     * Ask the adapter for the operation for the person, named as the caller of
     * a request on the guard, holding the session the guard serves.
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
        return $this->adapter()->check($operation, $maxAge, $this->namedCallerOf($caller));
    }

    /**
     * The person as SSO takes the caller of a request on the guard, holding the
     * session the guard serves.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     *
     * @throws \Throwable
     */
    private function namedCallerOf(Person $person): SsoCaller
    {
        return Iam::callers()->of($this->requestCallerOf($person));
    }

    /**
     * Start and complete a `link` flow for the person, named as the caller of a
     * request on the guard, as SSO's flow start asks freshness, and answer its
     * handoff.
     *
     * @param  \Tests\Fixtures\Models\Person  $caller
     * @return \Tests\Fixtures\Sso\Handoff
     *
     * @throws \Throwable
     */
    private function linkHandoff(Person $caller): Handoff
    {
        return $this->handoff(Purpose::LINK, $caller, $this->namedCallerOf($caller)->sessionId);
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
