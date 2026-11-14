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
 * Integration tests for SSO's freshness contract over the freshness policy.
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
     * Arrange SSO with this package's freshness adapter bound.
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
     * A session within SSO's maximum age is fresh, and stale once older.
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
     * SSO's gate asks with the maximum age configured for the operation.
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
     * The application's stricter requirement for the operation applies.
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
     * No caller, as in a job or a command, is stale.
     *
     * @return void
     */
    public function testNoCallerIsStale(): void
    {
        self::assertSame(FreshnessOutcome::STALE, $this->adapter()->check(FreshnessOperation::CONNECTION_TRUST, self::MAX_AGE, null));
    }

    /**
     * A caller with no session is stale, and the policy is not asked.
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
     * A caller is judged only on its identity's own live session.
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
     * A caller whose identity reference names no identity throws.
     *
     * @return void
     */
    public function testACallerNamingNoIdentityThrows(): void
    {
        $this->expectException(UnresolvedReferenceException::class);

        $this->adapter()->check(FreshnessOperation::LINK_CREATE, self::MAX_AGE, new SsoCaller(new IdentityReference(Person::class, '404'), 'session'));
    }

    /**
     * Only the caller's own session on an access credential is named.
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
     * A caller whose identity is no model cannot be named.
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
     * Inside SSO's transaction the policy is asked for a current read.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testThePolicyIsAskedCurrentInsideSsosTransaction(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $caller   = $this->namedCallerOf($person);
        $recorder = $this->recordReadModes();
        $answer   = DB::transaction(fn (): FreshnessOutcome => $this->adapter()->check(FreshnessOperation::ENFORCEMENT_UPDATE, self::MAX_AGE, $caller));

        self::assertSame(FreshnessOutcome::FRESH, $answer);
        self::assertAskedOnlyIn($recorder, true);
        self::assertAskedOnlyBy($recorder, FreshnessAdapter::class, FreshnessOperation::ENFORCEMENT_UPDATE->value);
    }

    /**
     * A caller named inside a transaction carries no session, so is stale.
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
     * A `link` for a caller fresh enough is created.
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
        self::assertAskedOnlyIn($recorder, true);
        self::assertAskedOnlyBy($recorder, FreshnessAdapter::class, FreshnessOperation::LINK_CREATE->value);
        self::assertSame(1, DB::table('sso_links')->count());
    }

    /**
     * A `link` for a stale caller is refused as `freshness_required`.
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
     * A caller holding another person's session cannot redeem a `link`.
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
     * A `link` redeemed inside the caller's own transaction is refused.
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
     * A `link` flow started for a caller with no session is refused.
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
     * Ask the adapter about the operation for the person as the caller.
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
     * The person as SSO takes a request's caller on the guard.
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
     * Start and complete a `link` flow for the person, and answer its handoff.
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
