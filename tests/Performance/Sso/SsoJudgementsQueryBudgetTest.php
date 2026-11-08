<?php

declare(strict_types = 1);

namespace Tests\Performance\Sso;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\ApplicationPolicyAdapter;
use SineMacula\Laravel\Iam\Sso\CallerScope;
use SineMacula\Laravel\Iam\Sso\ExternalEvidencePolicyAdapter;
use SineMacula\Laravel\Iam\Sso\FreshnessAdapter;
use SineMacula\Laravel\Iam\Sso\LinkEmailMatcherAdapter;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Linking\LinkEmailQuery;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Performance\PerformanceContractTestCase;

/**
 * The statements SSO's judgements make when this package answers them, so a
 * read added to one is seen here: a link e-mail match reads each kind of
 * identity once; freshness reads the session and its proofs, as
 * `laravel-authentication`'s policy does, for a caller handed in, and nothing
 * with no caller handed in, however fresh the session the request is served
 * with; the application's external sign-in reads no table; and the external
 * evidence policy reads nothing while MFA's default combination policy finds
 * the evidence meets nothing, a tenant's requirement included.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkEmailMatcherAdapter::class)]
#[CoversClass(FreshnessAdapter::class)]
#[CoversClass(CallerScope::class)]
#[CoversClass(ApplicationPolicyAdapter::class)]
#[CoversClass(ExternalEvidencePolicyAdapter::class)]
final class SsoJudgementsQueryBudgetTest extends PerformanceContractTestCase
{
    use MigratesMembers, SignsInPeople;

    /**
     * A link e-mail match, with one kind of identity a session guard signs in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkEmailMatch(): void
    {
        $this->createPerson('ada@example.test');

        $matcher = $this->app?->make(LinkEmailMatcher::class) ?? self::fail('The application has not booted.');
        $query   = new LinkEmailQuery('tenant-1', 'Ada@Example.test', 'example.test');

        // Reads (1): the people holding the e-mail's normal form.
        $this->assertQueryBudget(1, 0, static fn (): mixed => $matcher->match($query));
    }

    /**
     * A freshness check with no caller handed in, and of the session a caller
     * handed in is served with.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFreshnessCheck(): void
    {
        $freshness = $this->app?->make(Freshness::class) ?? self::fail('The application has not booted.');
        $person    = $this->createPerson();

        // Reads (0): with no one signed in there is no session to read.
        $this->assertQueryBudget(0, 0, static fn (): mixed => $freshness->check(FreshnessOperation::LINK_REMOVE, 300));

        $this->signInAndActOnSession($person);

        // Reads (0): with no caller handed in, the session the request is
        // served with is never judged.
        $this->assertQueryBudget(0, 0, static fn (): mixed => $freshness->check(FreshnessOperation::LINK_REMOVE, 300));

        // Reads (2): laravel-authentication's policy reads the session again
        // and then its newest proof that meets the requirement.
        $check  = static fn (): mixed => $freshness->check(FreshnessOperation::LINK_REMOVE, 300);
        $caller = $this->requestCallerOf($person);

        $this->assertQueryBudget(2, 0, static fn (): mixed => Iam::callers()->run($caller, $check));
    }

    /**
     * The application's external sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationsExternalSignIn(): void
    {
        $policy      = $this->app?->make(ApplicationPolicy::class) ?? self::fail('The application has not booted.');
        $application = Application::fromSettings(self::GUARD, ['redirect_uri' => 'https://app.iam.test/sso']);

        // Reads (0): the guard's methods are configuration.
        $this->assertQueryBudget(0, 0, static fn (): mixed => $policy->externalSignIn($application));
    }

    /**
     * Accepted evidence judged for a tenant's requirement under MFA's default
     * combination policy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEvidenceMfasDefaultFindsMeetsNothing(): void
    {
        $policy   = $this->app?->make(ExternalEvidencePolicy::class) ?? self::fail('The application has not booted.');
        $evidence = new ExternalEvidence(['pwd', 'mfa'], null, now()->subMinute());
        $subject  = new EvidenceSubject($this->createPerson(), self::GUARD, 'connection-1', now()->toImmutable(), new ClaimedTenant('tenant-1'));
        $required = new Requirement(multifactor: new RequirementPart);

        // Reads (0): MFA's policy is asked first, and the tenant's trust is
        // read only for evidence it finds meets the requirement.
        $this->assertQueryBudget(0, 0, static fn (): mixed => $policy->meets($evidence, $required, $subject));
    }
}
