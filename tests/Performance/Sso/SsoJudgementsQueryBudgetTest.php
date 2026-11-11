<?php

declare(strict_types = 1);

namespace Tests\Performance\Sso;

use Illuminate\Contracts\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\ApplicationPolicyAdapter;
use SineMacula\Laravel\Iam\Sso\ExternalEvidencePolicyAdapter;
use SineMacula\Laravel\Iam\Sso\FreshnessAdapter;
use SineMacula\Laravel\Iam\Sso\LinkEmailMatcherAdapter;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Linking\LinkEmailQuery;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Performance\PerformanceContractTestCase;

/**
 * The statements SSO's judgements make when this package answers them, so a
 * read added to one is seen here: a link e-mail match reads each kind of
 * identity once; freshness reads the caller's identity and its session, then
 * the session and its proofs, as `laravel-authentication`'s policy does, and
 * nothing for no caller or a caller with no session, however fresh the session
 * the request is served with; the application's external sign-in reads no
 * table; and the external evidence policy reads nothing while MFA's default
 * combination policy finds the evidence meets nothing, a tenant's requirement
 * included.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkEmailMatcherAdapter::class)]
#[CoversClass(FreshnessAdapter::class)]
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
     * A freshness check for no caller, for a caller with no session, and of the
     * session a caller names.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFreshnessCheck(): void
    {
        $freshness = $this->app?->make(Freshness::class) ?? self::fail('The application has not booted.');
        $person    = $this->createPerson();

        // Reads (0): with no caller there is no session to read.
        $this->assertQueryBudget(0, 0, static fn (): mixed => $freshness->check(FreshnessOperation::LINK_REMOVE, 300, null));

        $this->signInAndActOnSession($person);

        $caller = Iam::callers()->of($this->requestCallerOf($person));
        $bare   = new Caller($caller->identity);

        // Reads (0): a caller with no session names none to judge, however
        // fresh the session the request is served with.
        $this->assertQueryBudget(0, 0, static fn (): mixed => $freshness->check(FreshnessOperation::LINK_REMOVE, 300, $bare));

        // Reads (4): the caller's identity and its session, then
        // laravel-authentication's policy reads the session again and its
        // newest proof that meets the requirement.
        $this->assertQueryBudget(4, 0, static fn (): mixed => $freshness->check(FreshnessOperation::LINK_REMOVE, 300, $caller));
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
        $app         = $this->app ?? self::fail('The application has not booted.');
        $policy      = $app->make(ApplicationPolicy::class);
        $application = Application::fromSettings($app->make(Repository::class), self::GUARD, ['redirect_uri' => 'https://app.iam.test/sso']);

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
