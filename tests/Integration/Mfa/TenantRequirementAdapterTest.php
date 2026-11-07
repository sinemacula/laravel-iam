<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement as AuthenticationRequirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\ActiveTenantResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\TenantRequirementAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel as MfaLevel;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\TenantRequirementTests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\TestCase;

/**
 * Integration tests for MFA's tenant requirement, answered from the
 * application's tenant MFA requirement (IAM-4.5): it passes MFA's own
 * `TenantRequirement` contract kit (IAM-8.3), keeping no state between calls;
 * the application's answer for exactly the tenant MFA names is translated part
 * by part, the same answer `laravel-authentication`'s tenant authentication
 * policy is given; MFA composes it into the session's requirement once the
 * session acts in the tenant; with no requirement named nothing is required;
 * and a tenant that resolves to none, or a requirement that cannot answer,
 * throws rather than answer that nothing is required (IAM-8.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantRequirementAdapter::class)]
final class TenantRequirementAdapterTest extends TestCase
{
    use MigratesMembers, SignsInPeople, TenantRequirementTests;

    /** @var string The tenant the session acts in. */
    private const string TENANT = 'tenant-1';

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement The application's requirement. */
    private ?FakeTenantMfaRequirement $requirements = null;

    /**
     * Bind a tenancy in which every tenant resolves, and the application's
     * requirement: the kit's tenant requires multifactor authentication, and
     * its other tenant nothing.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(TenantResolver::class, new OpenTenancy);

        $this->requirements = FakeTenantMfaRequirement::fake($this->app)->require('contract-tenant', new AuthenticationRequirement(multifactor: new RequirementPart(300)));
    }

    /**
     * The adapter is MFA's tenant requirement bound.
     *
     * @return void
     */
    public function testTheAdapterIsMfasTenantRequirementBound(): void
    {
        self::assertInstanceOf(TenantRequirementAdapter::class, $this->tenantRequirement());
    }

    /**
     * The application's answer for exactly the tenant MFA names is translated
     * part by part, each part keeping its maximum age and the minimum level its
     * level, for the application asked.
     *
     * @return void
     */
    public function testTheApplicationsAnswerIsTranslatedForMfa(): void
    {
        $this->requirements()->require(self::TENANT, new AuthenticationRequirement(
            new RequirementPart(60),
            new RequirementPart(300),
            new LevelRequirement(AssuranceLevel::AAL2, 900),
            new RequirementPart,
        ));

        $expected = Requirement::none()
            ->withAdditionalVerification(60)
            ->withMultifactor(300)
            ->withMinimumLevel(MfaLevel::AAL2, 900)
            ->withPhishingResistance();

        self::assertSame($expected->toArray(), $this->tenantRequirement()->requirementFor($this->tenantIdentity(), self::GUARD, self::TENANT)->toArray());
        self::assertSame(['tenant' => self::TENANT, 'application' => self::GUARD], $this->requirements()->asked()[0]);
    }

    /**
     * MFA is given the very answer `laravel-authentication`'s tenant
     * authentication policy is given for the tenant, so the two members never
     * disagree about it.
     *
     * @return void
     */
    public function testMfaIsGivenTheAnswerAuthenticationsPolicyIsGiven(): void
    {
        $person = $this->createPerson();

        $this->requirements()->require(self::TENANT, new AuthenticationRequirement(additionalVerification: new RequirementPart(120)));

        $policy  = $this->app?->make(TenantAuthenticationPolicy::class) ?? self::fail('The application has not booted.');
        $factor  = $policy->requirementFor(new TenantPolicyContext(self::GUARD, $person, $person, new ClaimedTenant(self::TENANT), null))->factor;
        $mfas    = $this->tenantRequirement()->requirementFor($person, self::GUARD, self::TENANT);
        $through = (new RequirementTranslator)->toMfa($factor);

        self::assertSame($through->toArray(), $mfas->toArray());
    }

    /**
     * Once the session acts in a tenant, MFA composes the tenant's requirement
     * into the session's own; before, no tenant's applies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfaComposesTheTenantsRequirementOnceTheSessionActsInIt(): void
    {
        $this->app?->bind(ActiveTenantResolver::class, ActiveTenantResolverAdapter::class);

        $this->requirements()->require(self::TENANT, new AuthenticationRequirement(additionalVerification: new RequirementPart(120)));

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        self::assertTrue(Mfa::requirement(self::servedCaller())->isEmpty());

        $this->actInTenant($person, self::TENANT);

        self::assertSame(Requirement::none()->withAdditionalVerification(120)->toArray(), Mfa::requirement(self::servedCaller())->toArray());
    }

    /**
     * With no requirement bound or named, a tenant requires nothing of MFA, and
     * nothing about it is resolved: a tenant the application's resolver does
     * not know is not refused for a requirement nobody asked for.
     *
     * @return void
     */
    public function testWithNoRequirementNamedATenantRequiresNothing(): void
    {
        $this->app?->offsetUnset(FakeTenantMfaRequirement::REQUIREMENT);
        $this->app?->instance(TenantResolver::class, new ResolveNoTenant);

        self::assertTrue($this->tenantRequirement()->requirementFor($this->tenantIdentity(), self::GUARD, self::TENANT)->isEmpty());
    }

    /**
     * A tenant id `laravel-authentication`'s resolver resolves to no tenant
     * throws, so MFA's judgement is refused rather than made as though the
     * tenant required nothing; the application's requirement is never asked.
     *
     * @return void
     */
    public function testATenantThatResolvesToNoneThrows(): void
    {
        $this->app?->instance(TenantResolver::class, new ResolveNoTenant);

        $thrown = self::thrownBy(fn (): Requirement => $this->tenantRequirement()->requirementFor($this->tenantIdentity(), self::GUARD, self::TENANT));

        self::assertInstanceOf(UnresolvedReferenceException::class, $thrown);
        self::assertSame(ReferenceKind::TENANT, $thrown->kind);
        self::assertSame([], $this->requirements()->asked());
    }

    /**
     * What the application's requirement throws propagates.
     *
     * @return void
     */
    public function testWhatTheApplicationsRequirementThrowsPropagates(): void
    {
        $failure = new \RuntimeException('The tenant\'s settings cannot be read.');

        $this->requirements()->failFor(self::TENANT, $failure);

        self::assertSame($failure, self::thrownBy(fn (): Requirement => $this->tenantRequirement()->requirementFor($this->tenantIdentity(), self::GUARD, self::TENANT)));
    }

    /**
     * The requirement under test, as MFA resolves it.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\TenantRequirement
     */
    #[\Override]
    protected function tenantRequirement(): TenantRequirement
    {
        return $this->app?->make(TenantRequirement::class) ?? self::fail('The application has not booted.');
    }

    /**
     * A person of the application.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function tenantIdentity(): MultiFactorAuthenticatable
    {
        return $this->createPerson();
    }

    /**
     * The guard people sign in on.
     *
     * @return string
     */
    #[\Override]
    protected function tenantApplication(): string
    {
        return self::GUARD;
    }

    /**
     * The application's requirement, as the test set it.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement
     */
    private function requirements(): FakeTenantMfaRequirement
    {
        return $this->requirements ?? self::fail('The requirement is not faked.');
    }

    /**
     * What the call threw, failing when it threw nothing.
     *
     * @param  \Closure(): mixed  $call
     * @return \Throwable
     */
    private static function thrownBy(\Closure $call): \Throwable
    {
        try {
            $call();
        } catch (\Throwable $thrown) {
            return $thrown;
        }

        self::fail('The tenant was answered.');
    }

    /**
     * Sign the person in again and act on the new session in the tenant.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $tenant
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function actInTenant(Person $person, string $tenant): EloquentSession&Model
    {
        $session = $this->signIn($person)->record;

        $session->forceFill([$session->getTenantIdName() => $tenant])->save();

        $this->actingOnSession($session, self::GUARD);

        return $session;
    }
}
