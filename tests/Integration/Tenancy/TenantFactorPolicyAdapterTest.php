<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenantFactorPolicyAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenantPolicyVersion;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Mfa\Pending\Concerns\ArrangesPendingSessions;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\TestCase;

/**
 * Integration tests for the tenant policy MFA's tenant requirement answers
 * alone, and for a tenant's factor at sign-in with and without SSO.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantFactorPolicyAdapter::class)]
#[CoversClass(TenantAuthenticationPolicyAdapter::class)]
final class TenantFactorPolicyAdapterTest extends TestCase
{
    use ArrangesPendingSessions;

    /** @var string The tenant whose requirement each test scripts. */
    private const string TENANT = 'tenant-1';

    /** @var string A tenant that requires nothing. */
    private const string OTHER_TENANT = 'tenant-2';

    /**
     * Let everyone act in every tenant.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);
    }

    /**
     * Without SSO's adapters the adapter is the tenant policy bound.
     *
     * @return void
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testWithoutSsoTheAdapterIsThePolicyBound(): void
    {
        self::assertInstanceOf(TenantFactorPolicyAdapter::class, $this->resolved(TenantAuthenticationPolicy::class));
    }

    /**
     * The tenant's MFA requirement is the further factor, and no connection.
     *
     * @return void
     */
    public function testTheTenantsRequirementIsTheFurtherFactorAlone(): void
    {
        $scripted = ScriptedTenantRequirement::bind($this->app)->require(self::TENANT, MfaRequirement::none()->withMultifactor(300));
        $person   = $this->createPerson();
        $asked    = $this->ask($person, new ClaimedTenant(self::TENANT));

        self::assertEquals(new Requirement(multifactor: new RequirementPart(300)), $asked->factor);
        self::assertNull($asked->connections);
        self::assertTrue($this->ask($person, new ClaimedTenant(self::OTHER_TENANT))->factor->isEmpty());
        self::assertSame([['tenant' => self::TENANT, 'application' => self::GUARD], ['tenant' => self::OTHER_TENANT, 'application' => self::GUARD]], $scripted->asked());
    }

    /**
     * The version is the requirement's, and changes only with it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheVersionChangesOnlyWithTheRequirement(): void
    {
        $scripted = ScriptedTenantRequirement::bind($this->app);
        $person   = $this->createPerson();
        $before   = $this->ask($person, new ClaimedTenant(self::TENANT));

        self::assertSame(TenantPolicyVersion::ofFactor(new Requirement), $before->version);
        self::assertSame($before->version, $this->ask($person, new ClaimedTenant(self::TENANT))->version);

        $scripted->require(self::TENANT, MfaRequirement::none()->withMultifactor(300));

        $after = $this->ask($person, new ClaimedTenant(self::TENANT));

        self::assertSame(TenantPolicyVersion::ofFactor($after->factor), $after->version);
        self::assertNotSame($before->version, $after->version);
    }

    /**
     * A tenant that cannot be named throws before MFA is asked.
     *
     * @return void
     */
    public function testATenantThatCannotBeNamedThrows(): void
    {
        $scripted = ScriptedTenantRequirement::bind($this->app);
        $tenant   = \Mockery::mock(Tenant::class);

        $tenant->allows('getTenantIdentifier')->andReturn('');

        try {
            $this->ask($this->createPerson(), $tenant);

            self::fail('The policy answered.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::TENANT, $exception->kind);
        }

        self::assertSame([], $scripted->asked());
    }

    /**
     * Without SSO a tenant's factor holds the sign-in until it is met.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testWithoutSsoATenantsFactorHoldsTheSignInUntilMet(): void
    {
        $this->assertATenantsFactorHoldsTheSignInUntilMet();
    }

    /**
     * With SSO a tenant's factor holds the sign-in until it is met.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithSsoATenantsFactorHoldsTheSignInUntilMet(): void
    {
        $this->assertATenantsFactorHoldsTheSignInUntilMet();
    }

    /**
     * Without SSO the identity's own requirement still holds the sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testWithoutSsoTheIdentitysRequirementStillHoldsTheSignIn(): void
    {
        $this->assertTheIdentitysRequirementHoldsTheSignIn();
    }

    /**
     * With SSO the identity's own requirement still holds the sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithSsoTheIdentitysRequirementStillHoldsTheSignIn(): void
    {
        $this->assertTheIdentitysRequirementHoldsTheSignIn();
    }

    /**
     * Without SSO a tightened requirement reaches the tenant's sessions.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testWithoutSsoATightenedRequirementReachesTheTenantsSessions(): void
    {
        Config::set('mfa.applications.' . self::GUARD . '.requirement', 'never');

        $scripted = ScriptedTenantRequirement::bind($this->app);
        $session  = $this->signInTo($this->createPerson(), self::TENANT)->session->record ?? self::fail('The person did not sign in.');
        $stored   = static fn (): object => DB::table('authentication_sessions')->where('id', $session->getKey())->first() ?? self::fail('The session was not stored.');

        self::assertSame(0, Iam::tenantPolicies()->changed(new ClaimedTenant(self::TENANT)));
        self::assertSame(TenantPolicyVersion::ofFactor(new Requirement), $stored()->tenant_policy_version);

        $scripted->require(self::TENANT, MfaRequirement::none()->withMultifactor());

        self::assertSame(1, Iam::tenantPolicies()->changed(new ClaimedTenant(self::TENANT)));
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $stored()->revoked_reason);
    }

    /**
     * Assert only the tenant that asks for a factor holds the sign-in, until
     * the person verifies one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function assertATenantsFactorHoldsTheSignInUntilMet(): void
    {
        Config::set('mfa.applications.' . self::GUARD . '.requirement', 'never');

        ScriptedTenantRequirement::bind($this->app)->require(self::TENANT, MfaRequirement::none()->withAdditionalVerification());

        $person = $this->createPerson();
        $factor = $this->confirmedFactor($person);

        self::assertTrue($this->signInTo($person, self::OTHER_TENANT)->isSignedIn());

        $this->assertHeldUntilVerified($person, $factor, self::TENANT);
    }

    /**
     * Assert the identity's requirement holds a sign-in to a tenant that asks
     * for nothing, until the person verifies a factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function assertTheIdentitysRequirementHoldsTheSignIn(): void
    {
        Config::set('mfa.applications.' . self::GUARD . '.requirement', 'always');

        ScriptedTenantRequirement::bind($this->app);

        $person = $this->createPerson();

        $this->assertHeldUntilVerified($person, $this->confirmedFactor($person), self::OTHER_TENANT);
    }

    /**
     * Assert a sign-in to the tenant waits pending until MFA verifies the
     * factor, and then acts in the tenant.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @param  string  $tenant
     * @return void
     *
     * @throws \Throwable
     */
    private function assertHeldUntilVerified(Person $person, Factor $factor, string $tenant): void
    {
        $pending = $this->signInTo($person, $tenant);

        self::assertTrue($pending->isPending(), (string) $pending->reason?->value);

        $credential = $pending->credential?->reveal() ?? self::fail('The pending sign-in carries no credential.');
        $result     = Mfa::verify(CallerContext::fromRequest(self::requestCarrying($credential)), Submission::factor($factor->getKey(), AuthenticatorApp::code($factor)));
        $completion = $result->completion();

        self::assertTrue($result->isVerified());
        self::assertInstanceOf(SignInResult::class, $completion);
        self::assertTrue($completion->isSignedIn(), (string) $completion->reason?->value);
        self::assertSame($tenant, $completion->session?->record->getTenantId());
    }

    /**
     * The person's password sign-in to the tenant.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInTo(Person $person, string $tenant): SignInResult
    {
        $context = new SignInContext(self::client(), tenant: TenantSelection::of($tenant));

        return $this->sessions()->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], $context);
    }

    /**
     * The factor-only policy's answer for the person acting in the tenant.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function ask(Person $person, Tenant $tenant): TenantRequirement
    {
        $policy = $this->app?->make(TenantFactorPolicyAdapter::class) ?? self::fail('The application has not booted.');

        return $policy->requirementFor(self::tenantPolicyContext($person, $person, $tenant, null, static fn (): ?string => null));
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
     * A confirmed TOTP factor of the person's on the application.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function confirmedFactor(Person $person): Factor
    {
        return Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => ProofOwner::of($person)->key,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
            'application'          => self::GUARD,
        ]);
    }
}
