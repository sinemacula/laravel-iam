<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\GrantScopeAdapter;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\LinkEligibilityAdapter;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Tenancy\PrincipalScopeAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenantMembershipAdapter;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Concerns\LinksByVerifiedDomain;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * End-to-end tests for SSO's linking judgements answered from the application's
 * memberships (IAM-7.4, IAM-6.8), through SSO's own flows and this package's
 * redemptions, against SSO's acceptance scenarios: a `link`, redeemed
 * standalone with the authenticated caller and writing no session, links a
 * member of the connection's tenant and refuses anyone else as
 * `link_ineligible`; and a first sign-in by a verified email of the tenant's
 * verified domain reserves a link that the sign-in's redemption activates, for
 * a member who accepted before the domain's verification, once the grant half
 * of the principal scope answers `within_tenant` too, while the grant half with
 * the authorization switch off (`UnknownGrantScope`), a membership accepted
 * since or never, and a person reaching beyond the tenant reserve nothing, the
 * sign-in going on as `unlinked`; and a verified domain link whose person comes
 * to hold another tenant's membership is latched suspended at its next sign-in,
 * its session revoked.
 *
 * The grant half is `laravel-authorization`'s grant scope query as this package
 * binds it (`GrantScopeAdapter`): a member who holds no grant beyond the tenant
 * is linked by its verified domain, and one granted a role in another tenant is
 * not. Where only the memberships are under test, the grant half is a test
 * binding of this package's own port (`GrantScope`) answering `within_tenant`.
 * The flows that commit run at the connection's own level on every engine, then
 * at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantScopeAdapter::class)]
#[CoversClass(LinkEligibilityAdapter::class)]
#[CoversClass(PrincipalScopeAdapter::class)]
#[CoversClass(TenantMembershipAdapter::class)]
final class TenancyThroughSsoTest extends TestCase
{
    use LinksByVerifiedDomain, MigratesAuthorization, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The role an administrator grants. */
    private const string ROLE = 'editor';

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeMemberships The application's memberships. */
    private ?FakeMemberships $memberships = null;

    /**
     * Arrange SSO without the link eligibility stand-in, so this package's
     * adapter answers, with the application's memberships holding nothing until
     * a test grants it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->app?->forgetInstance(LinkEligibility::class);
        $this->app?->offsetUnset(LinkEligibility::class);
        $this->app?->bind(LinkEligibility::class, LinkEligibilityAdapter::class);

        $this->memberships = FakeMemberships::fake($this->app);

        $this->app?->instance(TenantResolver::class, new OrganisationTenancy);
    }

    /**
     * A member of the connection's tenant is linked through a whole `link`
     * flow, redeemed standalone as the authenticated caller, and no session is
     * written.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMemberOfTheConnectionsTenantIsLinked(?string $level): void
    {
        self::runAtIsolationLevel($level);

        self::assertInstanceOf(LinkEligibilityAdapter::class, $this->resolved(LinkEligibility::class));

        $person = $this->createPerson();

        $this->memberships()->grant($person, Membership::of(self::TENANT, CarbonImmutable::now()->subDay()));

        $sessions = DB::table('authentication_sessions')->count();
        $linked   = $this->linkThroughFlow($person);

        self::assertEquals(self::referenceOf($person), $linked->linkedIdentity);
        self::assertSame($sessions, DB::table('authentication_sessions')->count());
    }

    /**
     * Rows of `[membership]`: each standing that makes a person ineligible to
     * link through the tenant's connection.
     *
     * @return iterable<string, array{0: ?\SineMacula\Laravel\Iam\Tenancy\Membership}>
     */
    public static function provideIneligible(): iterable
    {
        yield 'no membership' => [null];

        yield 'an invitation not taken up' => [Membership::of(self::TENANT)];

        yield 'another tenant\'s membership' => [Membership::of('tenant-2', CarbonImmutable::now()->subDay())];
    }

    /**
     * A person who is no accepted member of the connection's tenant is refused
     * as `link_ineligible` at the completion, and nothing is linked.
     *
     * @param  ?\SineMacula\Laravel\Iam\Tenancy\Membership  $membership
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIneligible')]
    public function testAnyoneElseIsRefusedAsIneligible(?Membership $membership): void
    {
        $person = $this->createPerson();

        if ($membership !== null) {
            $this->memberships()->grant($person, $membership);
        }

        self::assertSame(FailureReason::LINK_INELIGIBLE->value, $this->refusal(Purpose::LINK, $person));
        self::assertSame(0, DB::table('sso_links')->count());
    }

    /**
     * A member who accepted before the domain's verification, holding nothing
     * beyond the tenant, signs in for the first time by their verified email:
     * the completion reserves a link, and the sign-in's redemption activates
     * it, with verified domain provenance, and signs them in through it.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testADomainReservationLinksAMemberEndToEnd(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->domainMember();

        $this->grantsWithin();

        $signedIn = $this->signInByDomain();

        self::assertTrue($signedIn->isSignedIn(), (string) $signedIn->reason?->value);

        $link = DB::table('sso_links')->where('identity_id', self::keyOf($person))->first() ?? self::fail('No link was made.');

        self::assertSame($this->connectionId, $link->connection_id);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN->value, $link->provenance);
        self::assertNull($link->suspended_at);
        $session = $signedIn->session->record ?? self::fail('No session was established.');

        self::assertSame($link->id, DB::table('authentication_provenance')->where('session_id', self::keyOf($session))->value('link_id'));
    }

    /**
     * With the authorization capability off, the grant half answers `unknown`
     * (`UnknownGrantScope`), so the same member's first sign-in reserves
     * nothing and links nobody.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
    public function testWithTheAuthorizationSwitchOffTheGrantHalfReservesNothing(): void
    {
        $this->domainMember();

        self::assertSame(FailureReason::UNLINKED->value, $this->refusal(Purpose::SIGN_IN, null, self::byDomain()));
        self::assertSame(0, DB::table('sso_links')->count());
    }

    /**
     * With the grant half `laravel-authorization`'s grant scope query, a member
     * who holds no grant beyond the tenant, or grants in it alone, is linked by
     * the tenant's verified domain end to end.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheShippedGrantHalfLinksAMemberWithinTheTenant(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->domainMember();

        $this->grantRole($person, self::TENANT);

        $signedIn = $this->signInByDomain();

        self::assertTrue($signedIn->isSignedIn(), (string) $signedIn->reason?->value);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN->value, DB::table('sso_links')->where('identity_id', self::keyOf($person))->value('provenance'));
    }

    /**
     * With the grant half `laravel-authorization`'s grant scope query, a member
     * granted a role in another tenant reaches beyond the tenant, and is not
     * linked by its verified domain.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheShippedGrantHalfLinksNobodyGrantedBeyondTheTenant(): void
    {
        $person = $this->domainMember();

        $this->grantRole($person, 'tenant-2');

        self::assertSame(FailureReason::UNLINKED->value, $this->refusal(Purpose::SIGN_IN, null, self::byDomain()));
        self::assertSame(0, DB::table('sso_links')->count());
    }

    /**
     * Rows of `[memberships]`: what keeps a person of the domain from being
     * linked by it.
     *
     * @return iterable<string, array{0: \Closure(): list<\SineMacula\Laravel\Iam\Tenancy\Membership>}>
     */
    public static function provideUnlinkable(): iterable
    {
        yield 'accepted since the verification' => [static fn (): array => [Membership::of(self::TENANT, CarbonImmutable::now()->addMinute())]];

        yield 'never accepted' => [static fn (): array => [Membership::of(self::TENANT)]];

        yield 'another tenant\'s too' => [static fn (): array => [Membership::of(self::TENANT, CarbonImmutable::now()->subDay()), Membership::of('tenant-2')]];

        yield 'a platform principal too' => [static fn (): array => [Membership::of(self::TENANT, CarbonImmutable::now()->subDay()), Membership::platform()]];
    }

    /**
     * A membership accepted since the domain's verification, or never, or a
     * person reaching beyond the tenant, reserves nothing, even with the grant
     * half answering `within_tenant`.
     *
     * @param  \Closure(): list<\SineMacula\Laravel\Iam\Tenancy\Membership>  $memberships
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnlinkable')]
    public function testAPersonNotWithinTheTenantSinceTheVerificationIsNotLinked(\Closure $memberships): void
    {
        $person = $this->createVerifiedPerson();

        $this->verifyDomain();
        $this->grantsWithin();

        foreach ($memberships() as $membership) {
            $this->memberships()->grant($person, $membership);
        }

        self::assertSame(FailureReason::UNLINKED->value, $this->refusal(Purpose::SIGN_IN, null, self::byDomain()));
        self::assertSame(0, DB::table('sso_links')->count());
    }

    /**
     * A verified domain link whose person later holds another tenant's
     * membership is judged `outside_tenant` at its next resolution: the next
     * sign-in through it is refused as `link_suspended`, and the session it
     * established is revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkWhosePersonReachesBeyondTheTenantIsSuspended(): void
    {
        $person = $this->domainMember();

        $this->grantsWithin();

        $session = $this->signInByDomain()->session->record ?? self::fail('The member did not sign in.');

        $this->memberships()->grant($person, Membership::of('tenant-2', CarbonImmutable::now()));

        self::assertSame(FailureReason::LINK_SUSPENDED->value, $this->refusal(Purpose::SIGN_IN, null, self::byDomain()));
        self::assertNotNull(DB::table('authentication_sessions')->where('id', self::keyOf($session))->value('revoked_at'));
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
     * A person of the domain's verified email, a member of the tenant since two
     * days before the domain is verified, with the domain then verified and the
     * connection's linking by it turned on.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    private function domainMember(): Person
    {
        $person = $this->createVerifiedPerson();

        $this->memberships()->grant($person, Membership::of(self::TENANT, CarbonImmutable::now()->subDays(2)));
        $this->verifyDomain();

        return $person;
    }

    /**
     * The error a flow of the purpose for the identity given completes with,
     * the provider's token tailored as given, or `null` when it issued a code.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\Tests\Fixtures\Models\Person  $identity
     * @param  ?\Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $tailor
     * @return ?string
     *
     * @throws \Random\RandomException
     */
    private function refusal(Purpose $purpose, ?Person $identity = null, ?\Closure $tailor = null): ?string
    {
        $app      = $this->app      ?? self::fail('The application has not booted.');
        $provider = $this->provider ?? self::fail('SSO is not arranged.');
        $start    = $this->started($purpose, $this->connectionId, $identity, null);
        $grant    = $provider->authorize($start, $tailor);
        $request  = new CompletionRequest('GET', $grant->query(), []);
        $result   = $app->make(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $this->connectionId, $request, self::ssoClient());

        return HandoffRedirect::from($app->make(CompletionResponses::class)->from($result, 'GET'))->error;
    }

    /**
     * Grant the person a role in the tenant given, through
     * `laravel-authorization`, as an administrator would.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $tenantId
     * @return void
     *
     * @throws \Throwable
     */
    private function grantRole(Person $person, string $tenantId): void
    {
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        Role::query()->firstOrCreate(['name' => self::ROLE]);

        Iam::transaction(static fn () => $service->grantRole($person, self::ROLE, tenant: new Reference(Organisation::TYPE, $tenantId), includeSubtree: false));
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

    /**
     * The application's memberships.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeMemberships
     */
    private function memberships(): FakeMemberships
    {
        return $this->memberships ?? self::fail('The memberships are not arranged.');
    }
}
