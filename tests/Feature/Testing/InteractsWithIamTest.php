<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Testing\CallerCompletion;
use SineMacula\Laravel\Iam\Testing\CallerSession;
use SineMacula\Laravel\Iam\Testing\CallerSignIn;
use SineMacula\Laravel\Iam\Testing\Concerns\InteractsWithIam;
use SineMacula\Laravel\Iam\Testing\FixtureFactors;
use SineMacula\Laravel\Iam\Testing\VerifiedSession;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Testing\Concerns\InteractsWithMfa;
use SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder;
use SineMacula\Laravel\Mfa\Testing\LevelEvidence;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;
use SineMacula\Laravel\Sso\Sessions\Provenance;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Machine;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Testing\LeveledCombinationPolicy;
use Tests\Fixtures\Testing\Membership;
use Tests\Fixtures\Testing\ResolvesMemberships;
use Tests\TestCase;

/**
 * Feature tests for acting as a caller with every adapter bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallerSession::class)]
#[CoversClass(CallerSignIn::class)]
#[CoversClass(CallerCompletion::class)]
#[CoversClass(FixtureFactors::class)]
#[CoversClass(VerifiedSession::class)]
#[CoversClass(ProofStoreAdapter::class)]
#[CoversTrait(InteractsWithIam::class)]
final class InteractsWithIamTest extends TestCase
{
    use InteractsWithIam, InteractsWithMfa, MigratesMembers, SignsInPeople;

    /** @var string The route MFA's gate lets a session through at AAL2. */
    private const string AAL2_ROUTE = '/verified/aal2';

    /** @var string The route MFA's gate lets a session through at AAL3. */
    private const string AAL3_ROUTE = '/verified/aal3';

    /** @var string The route that answers the guard's active tenant. */
    private const string TENANT_ROUTE = '/caller/tenant';

    /** @var string The latest an SSO caller's session may last, as SSO capped it, an hour after the SSO caller signs in. */
    private const string SESSION_NOT_AFTER = '2026-11-08 11:00:00';

    /** @var string The version of the enforcement SSO judged an SSO caller's sign-in under. */
    private const string ENFORCEMENT_VERSION = 'enforcement-7';

    /** @var string A second guard people sign in on. */
    private const string OTHER_GUARD = 'console';

    /** @var string The guard machines authenticate on with an API key. */
    private const string MACHINE_GUARD = 'machines';

    /** @var string The tenant a caller acts in. */
    private const string TENANT = 'tenant-acme';

    /** @var string The connection an SSO caller signed in through. */
    private const string SSO_CONNECTION = 'connection-acme';

    /** @var string The link an SSO caller signed in through. */
    private const string LINK = 'link-acme';

    /** @var string What MFA's own helper is refused with, naming the helper that arranges a verified session instead. */
    private const string REFUSAL = 'Only laravel-authentication records a session\'s proofs; a further proof reaches it through a step-up or a pending completion,'
        . ' or, in a test, through InteractsWithIam::actingOnVerifiedSession().';

    /**
     * Without the recorder, MFA's `actingAsVerified()` is refused by the store.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfasActingAsVerifiedIsRefusedByThisPackagesStoreWithoutItsRecorder(): void
    {
        $person = $this->createPerson();

        $this->app?->offsetUnset(VerifiedSignInRecorder::class);
        $this->signInAndActOnSession($person);

        $this->expectException(ProofRefusedException::class);
        $this->expectExceptionMessage(self::REFUSAL);

        $this->actingAsVerified($person, AssuranceLevel::AAL2);
    }

    /**
     * A session verified at AAL2 passes MFA's route gate on the next request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerifiedSessionPassesMfasRouteGate(): void
    {
        $session = $this->signIn($this->createPerson())->record;

        $this->actingOnSession($session)->getJson(self::AAL2_ROUTE)->assertUnauthorized();

        $this->actingOnVerifiedSession($session)->getJson(self::AAL2_ROUTE)->assertOk()->assertExactJson(['reached' => true]);
    }

    /**
     * Code outside the test case can arrange a verified session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCodeOutsideTheTestCaseCanActOnAVerifiedSession(): void
    {
        $session = $this->signIn($this->createPerson())->record;
        $outside = \Closure::bind(static fn (InteractsWithIamTest $test): InteractsWithIamTest => $test->actingOnVerifiedSession($session), null, null);

        self::assertSame($this, $outside($this));

        $this->getJson(self::AAL2_ROUTE)->assertOk();
    }

    /**
     * Each level with its further proof's factor type, channel and reference.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Enums\AssuranceLevel, string, \SineMacula\Laravel\Mfa\Enums\ChannelKind, ?string, bool, list<string>}>
     */
    public static function levels(): iterable
    {
        yield 'AAL1, an email code' => [AssuranceLevel::AAL1, 'email', ChannelKind::EMAIL, 'verified@example.test', false, ['otp']];
        yield 'AAL2, an authenticator app' => [AssuranceLevel::AAL2, 'totp', ChannelKind::AUTHENTICATOR_APP, null, true, ['otp']];
        yield 'AAL3, a hardware-protected passkey' => [AssuranceLevel::AAL3, 'passkey', ChannelKind::PASSKEY, LevelEvidence::PASSKEY_REFERENCE, true, ['pop', 'user', 'hwk']];
    }

    /**
     * The further proof is recorded with a factor the person holds.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  string  $type
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $channel
     * @param  ?string  $reference
     * @param  bool  $multifactor
     * @param  list<string>  $methods
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('levels')]
    public function testTheFurtherProofIsRecordedWithAFactorThePersonHolds(
        AssuranceLevel $level,
        string $type,
        ChannelKind $channel,
        ?string $reference,
        bool $multifactor,
        array $methods,
    ): void {
        $this->app?->instance(CombinationPolicy::class, new LeveledCombinationPolicy);

        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;

        $this->actingOnVerifiedSession($session, $level);

        $factor   = $this->onlyFactorOf($person);
        $recorded = $this->furtherProofOf($session);
        $store    = $this->app?->make(ProofStore::class);
        $current  = $store?->currentSession($person, self::GUARD);
        $proofs   = $store === null || $current === null ? [] : $store->proofs($person, self::GUARD, $current);

        self::assertSame($type, $factor->getType());
        self::assertSame(FactorStatus::CONFIRMED, $factor->getStatus());
        self::assertSame(self::GUARD, $factor->getApplication());

        self::assertSame(AuthenticationPurpose::STEP_UP, $recorded->purpose);
        self::assertSame($type, $recorded->method);
        self::assertSame($factor->id, $recorded->factor);
        self::assertSame($channel->value, $recorded->channel->kind->value);
        self::assertSame($reference ?? $factor->id, $recorded->channel->reference);
        self::assertTrue($recorded->evaluation?->accepted);
        self::assertSame($multifactor, $recorded->evaluation->multifactor);
        self::assertSame($methods, $recorded->methods);

        self::assertSame([ProofKind::FIRST_FACTOR, ProofKind::ADDITIONAL_FACTOR], array_map(static fn (Proof $proof): ProofKind => $proof->kind, $proofs));
        self::assertSame($factor->id, $proofs[1]->reference);
    }

    /**
     * A passkey session passes an AAL3 gate under a policy that rates it AAL3.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAal3SessionPassesAnAal3GateUnderAPolicyThatRatesItSo(): void
    {
        $this->app?->instance(CombinationPolicy::class, new LeveledCombinationPolicy);

        $session = $this->signIn($this->createPerson())->record;

        $this->actingOnVerifiedSession($session, AssuranceLevel::AAL3)->getJson(self::AAL3_ROUTE)->assertOk();

        $observed = $this->furtherProofOf($session)->observed;

        self::assertTrue($observed->userPresence);
        self::assertTrue($observed->userVerification);
        self::assertTrue($observed->phishingResistant);
        self::assertSame(KeyProtection::HARDWARE->value, $observed->keyProtection?->value);
    }

    /**
     * AAL3 is refused under MFA's default policy, naming what is unmet.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAal3IsRefusedUnderAPolicyThatDoesNotRateItSo(): void
    {
        $session = $this->signIn($this->createPerson())->record;

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Requested aal3 with additional verification; reached aal2; unmet: minimum_level.');

        $this->actingOnVerifiedSession($session, AssuranceLevel::AAL3);
    }

    /**
     * A session already verified past the level asked for is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionAlreadyPastTheLevelIsRefused(): void
    {
        $session = $this->signIn($this->createPerson())->record;

        $this->actingOnVerifiedSession($session);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Requested aal1 with additional verification; reached aal2; unmet: none.');

        $this->actingOnVerifiedSession($session, AssuranceLevel::AAL1);
    }

    /**
     * The unclassified level is refused before anything changes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheUnclassifiedLevelIsRefusedBeforeAnythingChanges(): void
    {
        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;

        try {
            $this->actingOnVerifiedSession($session, AssuranceLevel::UNCLASSIFIED);

            self::fail('A session was verified at the unclassified level.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A session cannot be verified at the unclassified level: it supports no level.', $exception->getMessage());
        }

        self::assertSame(0, $person->authFactors()->count());
        self::assertCount(1, $this->proofsOf($session));
    }

    /**
     * A person acts on a live session they signed in to, holding one factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPersonActsOnASessionTheySignedInTo(): void
    {
        $person = $this->createPerson();

        $this->actingAsCaller($person);

        $session = $this->boundSession();

        $this->assertBoundIdentity($person)->assertBoundPrincipal($person)->assertBoundTenant(null)->assertBoundScopes(null);

        self::assertSame(SessionStatus::ACTIVE, $session->getStatus());
        self::assertSame(self::GUARD, $session->getGuard());
        self::assertSame(CallerSession::DEFAULT_METHOD, $session->getSignInMethod());
        self::assertNull($session->getTenantId());
        self::assertSame(CallerSignIn::CLIENT_IP, $session->getAttribute($session->getLastUsedIpName()));
        self::assertSame(CallerSignIn::CLIENT_AGENT, $session->getAttribute($session->getLastUsedUserAgentName()));
        self::assertCount(1, $this->proofsOf($session));
        self::assertSame(AuthenticationChannelKind::UNKNOWN, $this->firstFactorOf($session)?->channel->kind);
        self::assertSame([], Auth::context()?->toArray()[AuthenticationContext::NAMESPACE] ?? []);

        $this->getJson(self::AAL2_ROUTE)->assertUnauthorized();
    }

    /**
     * The session uses the principal and method given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrincipalAndTheMethodGivenAreTheSessions(): void
    {
        $person = $this->createPerson();

        $this->actingAsCaller($person, principal: $person, session: CallerSession::started('passkey'));

        $this->assertBoundPrincipal($person);

        self::assertSame('passkey', $this->boundSession()->getSignInMethod());
    }

    /**
     * A principal held beside the default is the one the session records.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalBesideTheDefaultIsTheSessions(): void
    {
        $person     = $this->createPerson();
        $membership = new Membership('membership-1', $person);

        $this->app?->instance(PrincipalResolver::class, new ResolvesMemberships([$membership]));

        $this->actingAsCaller($person, principal: $membership);

        $session = $this->boundSession();

        $this->assertBoundIdentity($person)->assertBoundPrincipal($membership);

        self::assertSame(Membership::class, $session->getAttribute('principal_type'));
        self::assertSame('membership-1', $session->getAttribute('principal_id'));
    }

    /**
     * A principal the identity does not hold is refused, leaving nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalTheIdentityDoesNotHoldIsRefused(): void
    {
        $person = $this->createPerson();
        $other  = $this->createPerson('other@example.test');

        $this->app?->instance(PrincipalResolver::class, new ResolvesMemberships([new Membership('membership-2', $other)]));

        try {
            $this->actingAsCaller($person, principal: new Membership('membership-2', $other));

            self::fail('A principal another identity holds was acted as.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith('The caller did not sign in on guard [api]:', $exception->getMessage());
        }

        self::assertSame(0, $person->sessions()->count());
    }

    /**
     * Signed in with credentials, the session holds the method's first factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerSignedInWithCredentialsHoldsTheMethodsFirstFactor(): void
    {
        $person = $this->createPerson();

        $this->actingAsCaller($person, session: self::withPassword($person));

        $session = $this->boundSession();

        self::assertSame('password', $session->getSignInMethod());
        self::assertSame(AuthenticationChannelKind::PASSWORD, $this->firstFactorOf($session)?->channel->kind);
    }

    /**
     * Credentials of another identity are refused and rolled back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCredentialsOfAnotherIdentityAreRefused(): void
    {
        $caller = $this->createPerson();
        $other  = $this->createPerson();

        try {
            $this->actingAsCaller($caller, session: self::withPassword($other));

            self::fail('The caller acted on another identity\'s session.');
        } catch (\LogicException $exception) {
            self::assertSame('The credentials signed in another identity on guard [api] than the caller.', $exception->getMessage());
        }

        self::assertSame(0, $caller->sessions()->count());
        self::assertSame(0, $other->sessions()->count());
    }

    /**
     * Credentials that do not verify refuse the sign-in, naming the reason.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCredentialsThatDoNotVerifyAreRefused(): void
    {
        $person = $this->createPerson();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The caller did not sign in on guard [api]: [invalid_credentials].');

        $this->actingAsCaller($person, session: CallerSession::signedIn(['email' => $person->email, 'password' => 'wrong']));
    }

    /**
     * Code outside the test case can act as a caller.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCodeOutsideTheTestCaseCanActAsACaller(): void
    {
        $person  = $this->createPerson();
        $outside = \Closure::bind(static fn (InteractsWithIamTest $test): InteractsWithIamTest => $test->actingAsCaller($person), null, null);

        self::assertSame($this, $outside($this));

        $this->assertBoundIdentity($person);
    }

    /**
     * A person is signed in on the guard named, which becomes the default.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPersonIsSignedInOnTheGuardNamed(): void
    {
        $this->app?->make('config')->set('auth.guards.' . self::OTHER_GUARD, [
            'driver'      => 'jwt',
            'provider'    => 'people',
            'application' => ['methods' => ['password']],
        ]);

        $person = $this->createPerson();

        $this->actingAsCaller($person, guard: self::OTHER_GUARD);

        $this->assertBoundIdentity($person, self::OTHER_GUARD)->assertBoundSession(null, self::GUARD);

        self::assertSame(self::OTHER_GUARD, Auth::getDefaultDriver());
        self::assertSame(1, $person->sessions()->where('guard', self::OTHER_GUARD)->count());
    }

    /**
     * The tenant is recorded on the session and bound on the guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTenantIsTheSessionsAndTheGuards(): void
    {
        $this->openTenancy();

        $person = $this->createPerson();

        $this->actingAsCaller($person, tenant: self::TENANT);

        self::assertSame(self::TENANT, $this->boundSession()->getTenantId());
        self::assertSame(self::TENANT, $this->app?->make(ActiveTenantResolver::class)->activeTenant($person, self::GUARD));
        self::assertSame(self::TENANT, Auth::tenant()?->getTenantIdentifier());

        $this->getJson(self::TENANT_ROUTE)->assertOk()->assertExactJson(['tenant' => self::TENANT]);
    }

    /**
     * A tenant named by an integer id is the tenant of that id's string.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantNamedByAnIntegerIsItsString(): void
    {
        $this->openTenancy();

        $this->actingAsCaller($this->createPerson(), tenant: 42);

        self::assertSame('42', $this->boundSession()->getTenantId());
        self::assertSame('42', Auth::tenant()?->getTenantIdentifier());
    }

    /**
     * A tenant the tenant resolver does not resolve is refused, never guessed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantTheResolverDoesNotResolveIsRefused(): void
    {
        $this->app?->instance(TenantAccess::class, new OpenTenancy);
        $this->app?->instance(TenantResolver::class, new class implements TenantResolver {
            /**
             * Resolve no tenant.
             *
             * @param  string  $tenantId
             * @return null
             */
            #[\Override]
            public function resolve(string $tenantId): null
            {
                return null;
            }
        });

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The caller did not sign in on guard [api]: [tenant_ineligible].');

        $this->actingAsCaller($this->createPerson(), tenant: self::TENANT);
    }

    /**
     * A tenant the sign-in admits but this package cannot resolve is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantThisPackageCannotResolveIsRefused(): void
    {
        $this->openTenancy();

        $resolver = new OpenTenancy;

        $this->app?->instance(TenantResolver::class, new class ($resolver) implements TenantResolver {
            /** @var int How many times a tenant was resolved. */
            private int $calls = 0;

            /**
             * Constructor.
             *
             * @param  \Tests\Fixtures\Resolvers\OpenTenancy  $resolver
             */
            public function __construct(

                /** The resolver the sign-in reads. */
                private readonly OpenTenancy $resolver,
            ) {}

            /**
             * Resolve the tenant for the sign-in, and no tenant after it.
             *
             * @param  string  $tenantId
             * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
             */
            #[\Override]
            public function resolve(string $tenantId): ?Tenant
            {
                return $this->calls++ === 0 ? $this->resolver->resolve($tenantId) : null;
            }
        });

        $this->expectException(UnresolvedReferenceException::class);

        $this->actingAsCaller($this->createPerson(), tenant: self::TENANT);
    }

    /**
     * Naming the principal's own tenant still needs a tenant resolver.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrincipalsOwnTenantNamedStillNeedsAResolver(): void
    {
        $person     = $this->createPerson();
        $membership = new Membership('membership-own', $person, new ClaimedTenant('tenant-own'));

        $this->app?->instance(PrincipalResolver::class, new ResolvesMemberships([$membership]));

        try {
            $this->actingAsCaller($person, principal: $membership, tenant: 'tenant-own');

            self::fail('The principal\'s own tenant was acted in with no tenant resolver.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertStringContainsString('tenant-own', $exception->getMessage());
        }

        self::assertSame('tenant-own', $this->boundSession()->getTenantId());
    }

    /**
     * With no tenant named, the principal's own tenant needs no resolver.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrincipalsOwnTenantLeftOutNeedsNoResolver(): void
    {
        $person     = $this->createPerson();
        $membership = new Membership('membership-own', $person, new ClaimedTenant('tenant-own'));

        $this->app?->instance(PrincipalResolver::class, new ResolvesMemberships([$membership]));

        $this->actingAsCaller($person, principal: $membership);

        self::assertSame('tenant-own', $this->boundSession()->getTenantId());
    }

    /**
     * A caller verified at a level passes MFA's route gate.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerifiedCallerPassesMfasRouteGate(): void
    {
        $person = $this->createPerson();

        $this->actingAsCaller($person, session: self::withPassword($person), verified: AssuranceLevel::AAL2)->getJson(self::AAL2_ROUTE)->assertOk();

        self::assertCount(2, $this->proofsOf($this->boundSession()));
        self::assertSame('totp', $this->onlyFactorOf($person)->getType());
    }

    /**
     * A level for a started session is refused before sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALevelForAStartedSessionIsRefusedBeforeTheCallerSignsIn(): void
    {
        $person = $this->createPerson();

        try {
            $this->actingAsCaller($person, verified: AssuranceLevel::AAL2);

            self::fail('A started session was verified.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A level needs a first factor MFA can judge: sign the caller in with CallerSession::signedIn() or throughSso().', $exception->getMessage());
        }

        self::assertSame(0, $person->sessions()->count());
    }

    /**
     * Each level asked through SSO and the level reached instead.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\AssuranceLevel, 1: string}>
     */
    public static function provideLevelsThroughSso(): iterable
    {
        yield 'AAL1' => [AssuranceLevel::AAL1, 'Requested aal1 with additional verification; reached unclassified; unmet: minimum_level.'];

        yield 'AAL2' => [AssuranceLevel::AAL2, 'Requested aal2 with additional verification; reached aal1; unmet: minimum_level.'];
    }

    /**
     * Under MFA's default policy, no level is verified through SSO.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  string  $reached
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideLevelsThroughSso')]
    public function testUnderMfasDefaultNoLevelIsVerifiedThroughSso(AssuranceLevel $level, string $reached): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage($reached);

        $this->actingAsCaller($this->createPerson(), session: CallerSession::throughSso(self::provenance()), verified: $level);
    }

    /**
     * The tenant, level and SSO provenance land on one session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryPartComposesOnOneSession(): void
    {
        $this->openTenancy();

        $this->app?->instance(CombinationPolicy::class, new LeveledCombinationPolicy);

        $person = $this->createPerson();

        $this->actingAsCaller($person, $person, self::TENANT, self::GUARD, CallerSession::throughSso(self::provenance()), AssuranceLevel::AAL3);

        $session = $this->boundSession();

        $this->assertBoundIdentity($person)->assertBoundPrincipal($person);

        self::assertSame(self::TENANT, $session->getTenantId());
        self::assertSame(self::TENANT, Auth::tenant()?->getTenantIdentifier());
        self::assertSame(CallerSession::EXTERNAL_METHOD, $session->getSignInMethod());
        self::assertSame(self::SSO_CONNECTION, Auth::context()?->get(AuthenticationContext::CONNECTION));
        self::assertSame('passkey', $this->onlyFactorOf($person)->getType());
        self::assertCount(2, $this->proofsOf($session));

        $this->getJson(self::AAL3_ROUTE)->assertOk();
    }

    /**
     * An SSO caller's session carries the provenance as its provider context.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnSsoCallerCarriesTheProvenanceOnTheSession(): void
    {
        $this->travelTo(CarbonImmutable::parse('2026-11-08 10:00:00'));

        $person     = $this->createPerson();
        $provenance = self::provenance(CarbonImmutable::parse(self::SESSION_NOT_AFTER));

        $this->actingAsCaller($person, session: CallerSession::throughSso($provenance));

        $session = $this->boundSession();
        $context = Auth::context();

        $this->assertBoundIdentity($person);

        self::assertSame(CallerSession::EXTERNAL_METHOD, $session->getSignInMethod());
        self::assertSame(self::SSO_CONNECTION, $this->firstFactorOf($session)?->channel->reference);
        self::assertSame(self::SSO_CONNECTION, $context?->get(AuthenticationContext::CONNECTION));
        self::assertSame(self::TENANT, $context->get(AuthenticationContext::TENANT));
        self::assertSame('oidc', $context->get(AuthenticationContext::PROTOCOL));
        self::assertSame(self::LINK, $context->get(AuthenticationContext::LINK));
        self::assertSame(['pwd', 'mfa'], $context->get(AuthenticationContext::PROVIDER_AMR));
        self::assertSame($provenance->providerAuthenticatedAt?->format(Provenance::INSTANT_FORMAT), $context->get(AuthenticationContext::PROVIDER_AUTH_TIME));
        self::assertSame('2026-11-01 09:00:00', $this->firstFactorOf($session)?->authenticatedAt->format('Y-m-d H:i:s'));
        self::assertSame(self::SESSION_NOT_AFTER, $session->getAbsoluteExpiresAt()?->format('Y-m-d H:i:s'));
        self::assertSame(self::ENFORCEMENT_VERSION, DB::table('authentication_provenance')->where('session_id', $session->getKey())->value('policy_version'));
    }

    /**
     * Provenance with no provider time signs in as authenticated now.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnSsoCallerWithNoProviderTimeAuthenticatedNow(): void
    {
        $this->travelTo(CarbonImmutable::parse('2026-11-08 10:15:30.750'));

        $this->actingAsCaller($this->createPerson(), session: CallerSession::throughSso(new Provenance(self::SSO_CONNECTION, self::TENANT, 'saml2', linkId: self::LINK)));

        $session = $this->boundSession();

        self::assertSame('2026-11-08 10:15:30.000000', $this->firstFactorOf($session)?->authenticatedAt->format('Y-m-d H:i:s.u'));
        self::assertSame('saml2', Auth::context()?->get(AuthenticationContext::PROTOCOL));
        self::assertNull(DB::table('authentication_provenance')->where('session_id', $session->getKey())->value('policy_version'));
    }

    /**
     * The SSO caller's redemption is forgotten once the sign-in returns.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSsoCallersRedemptionIsForgotten(): void
    {
        $person = $this->createPerson();

        $this->actingAsCaller($person, session: CallerSession::throughSso(self::provenance()));

        $records = $this->app?->make(AdmittedRedemptions::class);

        self::assertNull($records?->matching(self::SSO_CONNECTION, CallerSignIn::ISSUER, (new IdentityReferences)->reference($person)->id));
    }

    /**
     * Provenance with no link is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testProvenanceWithNoLinkIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Under laravel-iam an SSO session is established through a link: name the link the provenance admitted.');

        $this->actingAsCaller($this->createPerson(), session: CallerSession::throughSso(new Provenance(self::SSO_CONNECTION, self::TENANT, 'oidc')));
    }

    /**
     * A method the guard does not allow is refused, naming the reason.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMethodTheGuardDoesNotAllowIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessageMatches('/^The caller did not sign in on guard \[api\]: \[method_not_allowed\]\.$/');

        $this->actingAsCaller($this->createPerson(), session: CallerSession::started('magic_link'));
    }

    /**
     * The unclassified level is refused before the person is signed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheUnclassifiedLevelIsRefusedBeforeTheCallerSignsIn(): void
    {
        $person = $this->createPerson();

        try {
            $this->actingAsCaller($person, session: self::withPassword($person), verified: AssuranceLevel::UNCLASSIFIED);

            self::fail('A caller was verified at the unclassified level.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A session cannot be verified at the unclassified level: it supports no level.', $exception->getMessage());
        }

        self::assertSame(0, $person->sessions()->count());
    }

    /**
     * Scopes for a person are refused before anything is signed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testScopesForAPersonAreRefused(): void
    {
        $person = $this->createPerson();

        try {
            $this->actingAsCaller($person, scopes: ['reports:read']);

            self::fail('A person acted with scopes.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Scopes limit only a machine identity; a person acts on a session, which its sign-in limits.', $exception->getMessage());
        }

        self::assertSame(0, $person->sessions()->count());
    }

    /**
     * A machine acts without a session, limited to its scopes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMachineActsWithoutASessionLimitedToItsScopes(): void
    {
        $this->openTenancy();

        $machine   = $this->createMachine();
        $principal = self::principalOf($machine);

        $this->actingAsCaller($machine, $principal, self::TENANT, self::MACHINE_GUARD, scopes: ['reports:read']);

        $this->assertBoundIdentity($machine, self::MACHINE_GUARD)
            ->assertBoundPrincipal($principal, self::MACHINE_GUARD)
            ->assertBoundSession(null, self::MACHINE_GUARD)
            ->assertBoundScopes(['reports:read'], self::MACHINE_GUARD);

        $this->assertBoundTenant(new ClaimedTenant(self::TENANT), self::MACHINE_GUARD);

        $this->actingAsCaller($machine, $principal, guard: self::MACHINE_GUARD);

        $this->assertBoundScopes([], self::MACHINE_GUARD)->assertBoundTenant(null, self::MACHINE_GUARD);
    }

    /**
     * What a machine cannot hold: a session and an MFA level.
     *
     * @return iterable<string, array{0: ?\SineMacula\Laravel\Iam\Testing\CallerSession, 1: ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel}>
     */
    public static function sessionParts(): iterable
    {
        yield 'a session' => [CallerSession::started(), null];
        yield 'SSO provenance' => [CallerSession::throughSso(self::provenance()), null];
        yield 'an MFA level' => [null, AssuranceLevel::AAL2];
    }

    /**
     * A session or MFA level for a machine is refused.
     *
     * @param  ?\SineMacula\Laravel\Iam\Testing\CallerSession  $session
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('sessionParts')]
    public function testAMachineIsRefusedWhatOnlyASessionHolds(?CallerSession $session, ?AssuranceLevel $level): void
    {
        $machine = $this->createMachine();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A machine identity signs in to no session, so it is acted as with no session and no MFA level.');

        $this->actingAsCaller($machine, self::principalOf($machine), guard: self::MACHINE_GUARD, session: $session, verified: $level);
    }

    /**
     * A factor holder completes the pending sign-in with that factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPersonWhoHoldsAFactorIsSignedInWithIt(): void
    {
        $person = $this->createPerson();
        $held   = $this->holdFactor($person, 'totp');

        $this->actingAsCaller($person, session: self::withPassword($person));

        $session = $this->boundSession();
        $proofs  = $this->proofsOf($session);

        $this->assertBoundIdentity($person)->assertBoundPrincipal($person);

        self::assertSame(SessionStatus::ACTIVE, $session->getStatus());
        self::assertSame($held->id, $this->onlyFactorOf($person)->id);
        self::assertCount(2, $proofs);
        self::assertSame(AuthenticationPurpose::SIGN_IN, $proofs[0]->purpose);
        self::assertSame('totp', $proofs[0]->method);
        self::assertSame($held->id, $proofs[0]->factor);
        self::assertSame(AuthenticationChannelKind::AUTHENTICATOR_APP, $proofs[0]->channel->kind);
        self::assertSame($held->id, $proofs[0]->channel->reference);
        self::assertTrue($proofs[0]->evaluation?->accepted);
        self::assertTrue($proofs[0]->evaluation->multifactor);
        self::assertSame(['otp'], $proofs[0]->methods);
    }

    /**
     * Each level a holder is verified at, and the factor types they then hold.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\AssuranceLevel, 1: list<string>}>
     */
    public static function heldLevels(): iterable
    {
        yield 'AAL1' => [AssuranceLevel::AAL1, ['email', 'totp']];
        yield 'AAL2' => [AssuranceLevel::AAL2, ['totp']];
        yield 'AAL3' => [AssuranceLevel::AAL3, ['passkey', 'totp']];
    }

    /**
     * A factor holder is verified at exactly the level asked for.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  list<string>  $types
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('heldLevels')]
    public function testAPersonWhoHoldsAFactorIsVerifiedAtTheLevel(AssuranceLevel $level, array $types): void
    {
        $this->app?->instance(CombinationPolicy::class, new LeveledCombinationPolicy);

        $person = $this->createPerson();

        $this->holdFactor($person, 'totp');

        $this->actingAsCaller($person, session: self::withPassword($person), verified: $level);

        $this->getJson(self::AAL2_ROUTE)->assertStatus($level === AssuranceLevel::AAL1 ? 401 : 200);
        $this->getJson(self::AAL3_ROUTE)->assertStatus($level === AssuranceLevel::AAL3 ? 200 : 401);

        self::assertSame($types, $person->authFactors()->pluck('type')->sort()->values()->all());
        self::assertCount(3, $this->proofsOf($this->boundSession()));
    }

    /**
     * A factor holder signed in through SSO keeps the provenance.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPersonWhoHoldsAFactorIsSignedInThroughSsoWithIt(): void
    {
        $person = $this->createPerson();
        $held   = $this->holdFactor($person, 'totp');

        $this->actingAsCaller($person, session: CallerSession::throughSso(self::provenance()));

        $proofs = $this->proofsOf($this->boundSession());

        self::assertSame(CallerSession::EXTERNAL_METHOD, $this->boundSession()->getSignInMethod());
        self::assertSame(self::SSO_CONNECTION, Auth::context()?->get(AuthenticationContext::CONNECTION));
        self::assertCount(2, $proofs);
        self::assertSame($held->id, $proofs[0]->factor);
        self::assertSame(AuthenticationPurpose::SIGN_IN, $proofs[0]->purpose);
    }

    /**
     * A holder verified at AAL1 completes the sign-in with an email code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHolderVerifiedAtAal1CompletesTheSignInWithAal1sEvidence(): void
    {
        $person = $this->createPerson();

        $this->holdFactor($person, 'totp');

        $this->actingAsCaller($person, session: self::withPassword($person), verified: AssuranceLevel::AAL1);

        $proofs = $this->proofsOf($this->boundSession());

        self::assertCount(3, $proofs);
        self::assertSame('email', $proofs[1]->method);
        self::assertSame('verified@example.test', $proofs[1]->channel->reference);
        self::assertFalse($proofs[1]->evaluation?->multifactor);
        self::assertSame(['email', 'totp'], $person->authFactors()->pluck('type')->sort()->values()->all());

        $this->getJson(self::AAL2_ROUTE)->assertUnauthorized();
    }

    /**
     * A started session of a factor holder is refused, naming what to do.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStartedSessionOfAHolderIsRefusedNamingWhatToDo(): void
    {
        $person = $this->createPerson();

        $this->holdFactor($person, 'totp');

        try {
            $this->actingAsCaller($person);

            self::fail('A started session of a holder was acted on.');
        } catch (\LogicException $exception) {
            self::assertSame(
                'The caller did not sign in on guard [api]: [pending: mfa]. A started session holds no first factor MFA can judge, so the further factor'
                . ' the application requires of a person who holds one cannot complete it: sign the caller in with CallerSession::signedIn() or throughSso().',
                $exception->getMessage(),
            );
        }

        self::assertSame(0, $person->sessions()->count());
        self::assertSame(1, $person->authFactors()->count());
    }

    /**
     * Only a sign-in waiting first on a further factor is completed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyASignInWaitingFirstOnAFurtherFactorIsCompleted(): void
    {
        $person = $this->createPerson();

        $this->holdFactor($person, 'totp');

        $result  = $this->attemptSignIn($person);
        $pending = $result->pending ?? self::fail('The holder\'s sign-in was not left pending.');
        $choice  = new PendingSession(
            $pending->id,
            $pending->guard,
            $pending->identity,
            null,
            null,
            [PendingRequirement::PRINCIPAL],
            $pending->method,
            $pending->expiresAt,
            $pending->session,
            $pending->requirement,
            $pending->firstFactor,
        );

        $completion = $this->app?->make(CallerCompletion::class) ?? self::fail('No completion.');

        foreach ([SignInResult::pending($choice, $result->credential), SignInResult::pending($pending)] as $handed) {
            self::assertSame($handed, $completion->complete($handed, self::GUARD, null, self::client()));
        }

        self::assertSame(PendingRequirement::MFA, $pending->requires[0]);
        self::assertSame(1, $person->authFactors()->count());
        self::assertSame([PendingRequirement::MFA], $this->sessions()->pending($result->credential ?? self::fail('No credential.'))?->requires);
    }

    /**
     * A further proof after a started session's first factor leaves it pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofAfterAStartedSessionsFirstFactorLeavesItPending(): void
    {
        $person = $this->createPerson();

        $this->holdFactor($person, 'totp');

        $factor  = new FirstFactor($person, new Channel(AuthenticationChannelKind::UNKNOWN));
        $started = $this->sessions()->start($factor, null, CallerSession::DEFAULT_METHOD, new SignInContext(self::client()));
        $result  = $this->app?->make(CrossMemberTransaction::class)->run(
            fn (): SignInResult => $this->app?->make(CallerCompletion::class)->complete($started, self::GUARD, null, self::client()) ?? self::fail('No completion.'),
        );

        self::assertTrue($result?->isPending());
        self::assertSame([PendingRequirement::MFA], $result->pending?->requires);
        self::assertSame(1, $person->authFactors()->count());
    }

    /**
     * A verified person can be acted as again, each time on a new session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerifiedPersonCanBeActedAsAgain(): void
    {
        $this->openTenancy();

        $this->app?->instance(CombinationPolicy::class, new LeveledCombinationPolicy);

        $person = $this->createPerson();

        $this->actingAsCaller($person, tenant: self::TENANT, session: self::withPassword($person), verified: AssuranceLevel::AAL2);

        $first = $this->boundSession();

        $this->actingAsCaller($person, tenant: 'tenant-other', session: self::withPassword($person), verified: AssuranceLevel::AAL2)->getJson(self::AAL2_ROUTE)->assertOk();

        $second = $this->boundSession();

        self::assertNotSame($first->getKey(), $second->getKey());
        self::assertSame('tenant-other', $second->getTenantId());
        self::assertSame('totp', $this->onlyFactorOf($person)->getType());

        $this->actingAsCaller($person, session: self::withPassword($person), verified: AssuranceLevel::AAL3)->getJson(self::AAL3_ROUTE)->assertOk();

        self::assertSame(2, $person->authFactors()->count());

        $this->actingAsCaller($person, session: self::withPassword($person));

        self::assertCount(2, $this->proofsOf($this->boundSession()));
        self::assertSame(2, $person->authFactors()->count());
    }

    /**
     * Credentials are held wrapped, so no dump or export shows them.
     *
     * @return void
     */
    public function testTheCredentialsAreHeldWrapped(): void
    {
        $session = CallerSession::signedIn(['email' => 'ada@example.test', 'password' => self::PASSWORD]);

        self::assertSame(['email' => 'ada@example.test', 'password' => self::PASSWORD], $session->credentials());
        self::assertStringNotContainsString(self::PASSWORD, print_r($session, true));
        self::assertTrue($session->provesFirstFactor());
        self::assertFalse(CallerSession::started()->provesFirstFactor());
        self::assertNull(CallerSession::started()->credentials());
        self::assertTrue(CallerSession::throughSso(self::provenance())->provesFirstFactor());
    }

    /**
     * Define the routes MFA's gate guards, on the stateless guard.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->get(self::AAL2_ROUTE, static fn (): JsonResponse => new JsonResponse(['reached' => true]))
            ->middleware(['auth:' . self::GUARD, 'mfa:level=aal2']);

        $router->get(self::AAL3_ROUTE, static fn (): JsonResponse => new JsonResponse(['reached' => true]))
            ->middleware(['auth:' . self::GUARD, 'mfa:level=aal3']);

        $router->get(self::TENANT_ROUTE, static fn (): JsonResponse => new JsonResponse(['tenant' => Auth::tenant()?->getTenantIdentifier()]))
            ->middleware(['auth:' . self::GUARD]);
    }

    /**
     * Allow passkey and `external_provider` sign-ins beside the password.
     *
     * @return list<string>
     */
    #[\Override]
    protected function signInMethods(): array
    {
        return ['password', 'passkey', 'external_provider'];
    }

    /**
     * Declare an API key machine guard and create a machine.
     *
     * @return \Tests\Fixtures\Models\Machine
     */
    private function createMachine(): Machine
    {
        $this->app?->make('config')->set('auth.guards.' . self::MACHINE_GUARD, ['driver' => 'api_key', 'provider' => 'machines']);
        $this->app?->make('config')->set('auth.providers.machines', ['driver' => 'model', 'model' => Machine::class]);

        return Machine::query()->create(['name' => 'Reporting']);
    }

    /**
     * The principal the machine acts as.
     *
     * @param  \Tests\Fixtures\Models\Machine  $machine
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private static function principalOf(Machine $machine): Principal
    {
        return new readonly class ($machine) implements Principal {
            /**
             * Constructor.
             *
             * @param  \Tests\Fixtures\Models\Machine  $machine
             */
            public function __construct(

                /** The machine the principal belongs to. */
                private Machine $machine,
            ) {}

            /**
             * The principal's identifier: the machine's key.
             *
             * @return mixed
             */
            #[\Override]
            public function getPrincipalIdentifier(): mixed
            {
                return $this->machine->getKey();
            }

            /**
             * The machine the principal belongs to.
             *
             * @return \SineMacula\Laravel\Authentication\Contracts\Identity
             */
            #[\Override]
            public function getIdentity(): Identity
            {
                return $this->machine;
            }

            /**
             * No tenant of its own.
             *
             * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
             */
            #[\Override]
            public function getTenant(): ?Tenant
            {
                return null;
            }
        };
    }

    /**
     * The tenant resolver and access that admit every tenant.
     *
     * @return void
     */
    private function openTenancy(): void
    {
        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);
    }

    /**
     * The provenance an SSO caller signs in with, capped at the time given.
     *
     * @param  ?\Carbon\CarbonImmutable  $notAfter
     * @return \SineMacula\Laravel\Sso\Sessions\Provenance
     */
    private static function provenance(?CarbonImmutable $notAfter = null): Provenance
    {
        return new Provenance(
            self::SSO_CONNECTION,
            self::TENANT,
            'oidc',
            CarbonImmutable::parse('2026-11-01 09:00:00'),
            ['pwd', 'mfa'],
            linkId: self::LINK,
            sessionNotAfter: $notAfter,
            enforcementVersion: self::ENFORCEMENT_VERSION,
        );
    }

    /**
     * A session the person signs in to with their password.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Iam\Testing\CallerSession
     */
    private static function withPassword(Person $person): CallerSession
    {
        return CallerSession::signedIn(['email' => $person->email, 'password' => self::PASSWORD]);
    }

    /**
     * The session the guard people sign in on has bound.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function boundSession(): EloquentSession&Model
    {
        $session = $this->app?->make(CurrentSession::class)->guard(self::GUARD)->session();

        self::assertInstanceOf(EloquentSession::class, $session);
        self::assertInstanceOf(Model::class, $session);

        return $session;
    }

    /**
     * Give the person a confirmed factor of the type.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $type
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     *
     * @throws \Throwable
     */
    private function holdFactor(Person $person, string $type): Factor
    {
        $factor = new Factor;
        $owner  = $factor->authenticatable();

        $factor->forceFill([
            $owner->getMorphType()        => $person->getMorphClass(),
            $owner->getForeignKeyName()   => $person->getKey(),
            $factor->getTypeName()        => $type,
            $factor->getApplicationName() => self::GUARD,
        ]);

        $factor->confirm();
        $factor->persist();

        return $factor;
    }

    /**
     * The one factor the person holds.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function onlyFactorOf(Person $person): Factor
    {
        $factors = $person->authFactors()->get()->all();

        self::assertCount(1, $factors);
        self::assertInstanceOf(Factor::class, $factors[0]);

        return $factors[0];
    }

    /**
     * The session's only proof after the first factor.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \Throwable
     */
    private function furtherProofOf(EloquentSession&Model $session): RecordedProof
    {
        $proofs = $this->proofsOf($session);

        self::assertCount(2, $proofs);
        self::assertNotSame(AuthenticationChannelKind::PASSWORD, $proofs[0]->channel->kind);

        return $proofs[0];
    }
}
