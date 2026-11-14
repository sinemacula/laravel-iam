<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenantPolicyVersion;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Enforcement\EnforcementResult;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use Tests\Concerns\CountsLockingReads;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Sso\Handoff;
use Tests\Fixtures\Tenancy\ExemptsIdentities;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\TestCase;

/**
 * Integration tests for SSO enforcement through the tenant policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantAuthenticationPolicyAdapter::class)]
#[CoversClass(SessionRevocationAdapter::class)]
final class EnforcementThroughTenantPolicyTest extends TestCase
{
    use CountsLockingReads, MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var ?\Tests\Fixtures\Tenancy\ExemptsIdentities The application's break-glass rule. */
    private ?ExemptsIdentities $exemptions = null;

    /**
     * Arrange SSO enforcement, an open tenancy and an exemption rule.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        Config::set('sso.features.enforcement', true);

        $this->exemptions = new ExemptsIdentities;

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);
        $this->app?->instance(EnforcementExemption::class, $this->exemptions);

        Event::fake([ExemptionUsed::class, EnforcementChanged::class]);
    }

    /**
     * A sign-in names the enforcement version judged under the locks.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testASignInNamesTheEnforcementVersionJudgedUnderTheLocks(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->linkThroughFlow($this->createPerson());
        $this->signedIn($this->redeemInTenant($this->handoff()));

        $completed = $this->versionOf($this->enforcement()->update(self::TENANT, true, [$this->connectionId], self::ssoClient()));
        $handoff   = $this->handoff();
        $judged    = $this->versionOf($this->enforcement()->update(self::TENANT, true, [$this->connectionId, $this->makeConnection()], self::ssoClient()));
        $answer    = $this->redeemInTenant($handoff);

        self::assertNotSame($completed, $judged);
        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn(), (string) $answer->reason?->value);

        $session    = $answer->session->record                                                                    ?? self::fail('The sign-in established no session.');
        $provenance = DB::table('authentication_provenance')->where('session_id', self::keyOf($session))->first() ?? self::fail('The session has no provenance.');
        $policy     = $this->app?->make(Enforcement::class)->policy(self::TENANT, self::GUARD)                    ?? self::fail('The application has not booted.');

        self::assertSame($judged, $provenance->policy_version);
        self::assertSame($judged, $policy->version);
        self::assertSame(self::TENANT, $session->getTenantId());
        self::assertSame(TenantPolicyVersion::of($policy, null, new Requirement), $this->stored($session)->getTenantPolicyVersion());
        Event::assertNotDispatched(ExemptionUsed::class);
    }

    /**
     * A password sign-in in the enforcing tenant is refused.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAPasswordSignInInTheEnforcingTenantIsRefused(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->enforce();

        $sessions = DB::table('authentication_sessions')->count();
        $result   = $this->signInWithPassword($this->createPerson());

        self::assertTrue($result->isFailed());
        self::assertSame(FailureReason::SSO_REQUIRED, $result->reason);
        self::assertNull($result->session);
        self::assertSame($sessions, DB::table('authentication_sessions')->count());
        Event::assertNotDispatched(ExemptionUsed::class);
    }

    /**
     * An exempt person signs in with a password.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnExemptPersonSignsInWithAPassword(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $version = $this->enforce();
        $person  = $this->createPerson();

        $this->exemptions()->exempt(self::referenceOf($person));

        $result = $this->signInWithPassword($person);

        self::assertTrue($result->isSignedIn(), (string) $result->reason?->value);
        Event::assertDispatchedTimes(ExemptionUsed::class, 1);
        Event::assertDispatched(ExemptionUsed::class, static fn (ExemptionUsed $event): bool => $event->enforcementVersion === $version
            && $event->context->tenantId                                                                                   === self::TENANT
            && $event->context->application                                                                                === self::GUARD
            && $event->context->identityId                                                                                 === self::keyOf($person));
    }

    /**
     * An exempt redemption reports the exemption with its client.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnExemptRedemptionReportsTheExemptionWithItsClient(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $tenant  = 'tenant-2';
        $foreign = $this->makeConnection($tenant);

        $this->linkThroughFlow($person);

        DB::table('sso_connections')->where('id', $foreign)->update(['has_completed_sign_in' => true]);

        $version = $this->versionOf($this->enforcement()->update($tenant, true, [$foreign], self::ssoClient()));

        $this->exemptions()->exempt(self::referenceOf($person));

        $handoff = $this->handoff();
        $context = new SignInContext(new ClientContext('203.0.113.7', 'signing-in-agent'), tenant: TenantSelection::of($tenant));
        $session = $this->signedIn(Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, $context));

        self::assertSame($tenant, $session->getTenantId());
        Event::assertDispatchedTimes(ExemptionUsed::class, 1);
        Event::assertDispatched(ExemptionUsed::class, static fn (ExemptionUsed $event): bool => $event->enforcementVersion === $version
            && $event->context->tenantId                                                                                   === $tenant
            && $event->context->sessionId                                                                                  === null
            && $event->context->ip                                                                                         === '203.0.113.7'
            && $event->context->userAgent                                                                                  === 'signing-in-agent');

        $handoff = $this->handoff(Purpose::REAUTHENTICATE, $person, self::keyOf($session));
        $token   = Iam::reauthentications()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new ClientContext('198.51.100.9', 'renewing-agent'));

        self::assertInstanceOf(AccessTokenResult::class, $token);
        self::assertFalse($token->isFailed(), (string) $token->reason?->value);
        Event::assertDispatchedTimes(ExemptionUsed::class, 2);
        Event::assertDispatched(ExemptionUsed::class, static fn (ExemptionUsed $event): bool => $event->context->sessionId === self::keyOf($session)
            && $event->context->ip                                                                                         === '198.51.100.9'
            && $event->context->userAgent                                                                                  === 'renewing-agent');

        self::assertSame(0, $this->sessions()->tenantPolicyChanged(new ClaimedTenant($tenant)));
        Event::assertDispatchedTimes(ExemptionUsed::class, 3);
        Event::assertDispatched(ExemptionUsed::class, static fn (ExemptionUsed $event): bool => $event->context->sessionId === self::keyOf($session)
            && $event->context->ip                                                                                         === null
            && $event->context->userAgent                                                                                  === null);
    }

    /**
     * An enforcement change revokes the sessions the rule no longer allows.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnEnforcementChangeRevokesTheSessionsTheRuleNoLongerAllows(?string $level): void
    {
        self::runAtIsolationLevel($level);

        [$ada, $grace, $hopper] = [$this->createPerson(), $this->createPerson(), $this->createPerson()];

        $this->linkThroughFlow($ada);

        $external = $this->signedIn($this->redeemInTenant($this->handoff()));
        $password = $this->signedIn($this->signInWithPassword($grace));
        $exempt   = $this->signedIn($this->signInWithPassword($hopper));

        $this->exemptions()->exempt(self::referenceOf($hopper));

        $version = self::ruleVersionOf($this->enforcement()->update(self::TENANT, true, [$this->connectionId], self::ssoClient()));

        Event::assertDispatchedTimes(EnforcementChanged::class, 1);
        Event::assertDispatched(EnforcementChanged::class, static fn (EnforcementChanged $event): bool => $event->enabled && $event->version === $version);
        self::assertNull($this->stored($external)->getRevokedAt());
        self::assertNotNull($this->stored($password)->getRevokedAt());
        self::assertNull($this->stored($exempt)->getRevokedAt());
        Event::assertDispatchedTimes(ExemptionUsed::class, 2);
        Event::assertDispatched(ExemptionUsed::class, static fn (ExemptionUsed $event): bool => $event->context->sessionId === self::keyOf($exempt));
        Event::assertNotDispatched(ExemptionUsed::class, static fn (ExemptionUsed $event): bool => $event->context->sessionId !== self::keyOf($exempt));

        $this->versionOf($this->enforcement()->update(self::TENANT, false, [], self::ssoClient()));

        Event::assertDispatchedTimes(EnforcementChanged::class, 2);
        Event::assertDispatched(EnforcementChanged::class, static fn (EnforcementChanged $event): bool => !$event->enabled && $event->previousVersion === $version);
        self::assertNull($this->stored($external)->getRevokedAt());
        self::assertNull($this->stored($exempt)->getRevokedAt());
    }

    /**
     * A second pass that throws leaves the change durable.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testASecondPassThatThrowsLeavesTheChangeDurable(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $requirement = ScriptedTenantRequirement::bind($this->app);

        $this->linkThroughFlow($this->createPerson());

        $external = $this->signedIn($this->redeemInTenant($this->handoff()));
        $password = $this->signedIn($this->signInWithPassword($this->createPerson()));
        $failure  = new \RuntimeException('The requirement can no longer answer.');

        self::onceTheChangeCommits(static function () use ($requirement, $failure): void {
            $requirement->failFor(self::TENANT, $failure);
        });

        try {
            $this->enforcement()->update(self::TENANT, true, [$this->connectionId], self::ssoClient());

            self::fail('The second pass\'s failure did not propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        $policy = $this->app?->make(Enforcement::class)->policy(self::TENANT, self::GUARD) ?? self::fail('The application has not booted.');

        self::assertTrue($policy->isRequired());
        self::assertSame([$this->connectionId], $policy->connectionIds);
        self::assertNotNull($this->stored($password)->getRevokedAt());
        self::assertNull($this->stored($external)->getRevokedAt());
        Event::assertNotDispatched(EnforcementChanged::class);
    }

    /**
     * A withdrawn exemption reported as a policy change revokes the session.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAWithdrawnExemptionReportedAsAPolicyChangeRevokesTheExemptSession(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->enforce();

        $person = $this->createPerson();

        $this->exemptions()->exempt(self::referenceOf($person));

        $session = $this->signedIn($this->signInWithPassword($person));
        $tenant  = new ClaimedTenant(self::TENANT);

        $this->exemptions()->exemptNobody();

        self::assertNull($this->stored($session)->getRevokedAt(), 'The withdrawal alone judged the session.');
        self::assertSame(1, $this->sessions()->tenantPolicyChanged($tenant));
        self::assertNotNull($this->stored($session)->getRevokedAt());
    }

    /**
     * Another tenant's sessions are not judged.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnotherTenantsSessionsAreNotJudged(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->signedIn($this->signInWithPassword($this->createPerson(), 'tenant-2'));

        $this->enforce();

        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * A tenant MFA requirement revokes the sessions without its factor.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testATenantRequirementRevokesTheSessionsWithoutItsFactor(?string $level): void
    {
        self::runAtIsolationLevel($level);

        Config::set('sso.features.enforcement', false);

        $session = $this->signedIn($this->signInWithPassword($this->createPerson()));

        ScriptedTenantRequirement::bind($this->app)->require(self::TENANT, MfaRequirement::none()->withMultifactor());

        self::assertSame(1, $this->sessions()->tenantPolicyChanged(new ClaimedTenant(self::TENANT)));
        self::assertNotNull($this->stored($session)->getRevokedAt());
    }

    /**
     * An unchanged policy records the version answered.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnUnchangedPolicyIsRecordedAsTheVersionAnswered(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        $this->linkThroughFlow($person);
        $this->enforce(linked: true);

        $session = $this->signedIn($this->redeemInTenant($this->handoff()));
        $tenant  = new ClaimedTenant(self::TENANT);
        $policy  = $this->app?->make(TenantAuthenticationPolicy::class) ?? self::fail('The application has not booted.');
        $stored  = $this->stored($session);
        $answer  = $policy->requirementFor(self::tenantPolicyContext($person, $person, $tenant, $stored, fn (): ?string => $this->recordedConnectionOf($stored)));

        self::assertNotNull($answer->version);
        self::assertSame($answer->version, $this->stored($session)->getTenantPolicyVersion());
        self::assertSame(0, $this->sessions()->tenantPolicyChanged($tenant));
        self::assertSame($answer->version, $this->stored($session)->getTenantPolicyVersion());
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * The policy takes no lock under the session's lock.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testThePolicyTakesNoLockUnderTheSessionsLock(string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        $this->linkThroughFlow($person);
        $this->enforce(linked: true);

        $session    = $this->signedIn($this->redeemInTenant($this->handoff()));
        $policy     = $this->app?->make(TenantAuthenticationPolicy::class) ?? self::fail('The application has not booted.');
        $connection = $this->connectionId;
        $context    = self::tenantPolicyContext($person, $person, new ClaimedTenant(self::TENANT), $this->stored($session), static fn (): string => $connection);

        [$requirement, $locks] = $this->askedUnderTheSessionsLock($session, static fn (): TenantRequirement => $policy->requirementFor($context));

        self::assertSame([$this->connectionId], $requirement->connections);
        self::assertSame([], $this->exemptions()->asked());
        self::assertSame([], $locks, 'The policy took a lock of its own.');
    }

    /**
     * Redeem the handoff in the tenant for the tests' client.
     *
     * @param  \Tests\Fixtures\Sso\Handoff  $handoff
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function redeemInTenant(Handoff $handoff): RedemptionResult|SignInResult
    {
        $context = new SignInContext(self::client(), tenant: TenantSelection::of(self::TENANT));

        return Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, $context);
    }

    /**
     * Sign the person in with their password in the given tenant.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInWithPassword(Person $person, string $tenant = self::TENANT): SignInResult
    {
        $context = new SignInContext(self::client(), tenant: TenantSelection::of($tenant));

        return $this->sessions()->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], $context);
    }

    /**
     * The session the sign-in established, failing unless it is active.
     *
     * @param  mixed  $answer
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function signedIn(mixed $answer): EloquentSession&Model
    {
        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn(), (string) $answer->reason?->value);

        return $answer->session->record ?? self::fail('The sign-in established no session.');
    }

    /**
     * The session as it is stored now.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function stored(EloquentSession&Model $session): EloquentSession&Model
    {
        $stored = $session->newQuery()->find($session->getKey());

        self::assertInstanceOf(EloquentSession::class, $stored);
        self::assertInstanceOf(Model::class, $stored);

        return $stored;
    }

    /**
     * Require sessions in the tenant to come through the tests' connection.
     *
     * @param  bool  $linked
     * @return ?string
     *
     * @throws \Throwable
     */
    private function enforce(bool $linked = false): ?string
    {
        if (!$linked) {
            $this->linkThroughFlow($this->createPerson());
        }

        $handoff = $this->handoff();

        $this->signedIn(Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client())));

        return $this->versionOf($this->enforcement()->update(self::TENANT, true, [$this->connectionId], self::ssoClient()));
    }

    /**
     * SSO's enforcement service.
     *
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementService
     */
    private function enforcement(): EnforcementService
    {
        return $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');
    }

    /**
     * The application's break-glass rule.
     *
     * @return \Tests\Fixtures\Tenancy\ExemptsIdentities
     */
    private function exemptions(): ExemptsIdentities
    {
        return $this->exemptions ?? self::fail('The exemptions are not arranged.');
    }

    /**
     * The policy version after the change, failing unless it changed.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementResult  $result
     * @return ?string
     */
    private function versionOf(EnforcementResult $result): ?string
    {
        self::assertTrue($result->isChanged(), sprintf('The enforcement did not change: [%s].', $result->reason->value ?? $result->status->value));

        $tenantId = $result->enforcement->tenantId ?? self::fail('The change named no enforcement.');

        return $this->app?->make(Enforcement::class)->policy($tenantId, self::GUARD)->version;
    }

    /**
     * The changed rule's own version, as SSO's change event names it.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementResult  $result
     * @return ?string
     */
    private static function ruleVersionOf(EnforcementResult $result): ?string
    {
        self::assertTrue($result->isChanged(), sprintf('The enforcement did not change: [%s].', $result->reason->value ?? $result->status->value));

        return $result->enforcement?->version;
    }

    /**
     * Queue the callback for after the change commits, before pass two.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private static function onceTheChangeCommits(\Closure $callback): void
    {
        $queued = false;

        DB::connection(self::CONNECTION)->listen(static function (QueryExecuted $query) use (&$queued, $callback): void {

            if ($queued || $query->connection->transactionLevel() === 0 || !str_contains(strtolower($query->sql), 'authentication_sessions')) {
                return;
            }

            $queued = true;

            $query->connection->afterCommit($callback);
        });
    }
}
