<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Fixtures\Models\Person;

/**
 * Links a person by the tenant's verified domain through SSO's own flows: the
 * tests' tenant claims and verifies its domain for the tests' connection, which
 * links by it, and a person of a verified email of that domain signs in for the
 * first time, the provider asserting the organisation's value; the completion
 * reserves a link, and this package's redemption activates it.
 *
 * The grant half of the principal scope answering `within_tenant` is a test
 * binding of this package's own port (`grantsWithin()`), standing in for
 * `laravel-authorization`'s grant scope query so that a test of the memberships
 * alone needs no `laravel-authorization` grants. It is used with `RunsSsoFlows`
 * and `SignsInPeople`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait LinksByVerifiedDomain
{
    /** @var string The tenant's verified domain. */
    protected const string DOMAIN = 'example.com';

    /** @var string The person's verified email, of that domain. */
    protected const string EMAIL = 'ada@example.com';

    /**
     * A person whose email, of the domain, is verified.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    protected function createVerifiedPerson(): Person
    {
        $person = $this->createPerson(self::EMAIL);

        $person->forceFill(['email_verified_at' => now()->subYear()])->save();

        return $person;
    }

    /**
     * Turn linking by a verified domain on, claim and verify the domain for the
     * tests' connection, and turn the connection's linking on for its issuer,
     * shared, the organisation holding the domain under `hd`.
     *
     * @return void
     */
    protected function verifyDomain(): void
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        Config::set('sso.features.domain_linking', true);

        $dns = new FakeDnsResolver;

        $app->instance(DnsResolver::class, $dns);

        $domains = $app->make(DomainService::class);
        $result  = $domains->claim(self::TENANT, $this->connectionId, self::DOMAIN, self::ssoClient());
        $claimed = $result->domain ?? self::fail(sprintf('The domain was not claimed: [%s].', $result->reason->value ?? $result->status->value));

        $dns->publishes($claimed);

        self::assertSame(DomainStatus::VERIFIED, $domains->verify(self::TENANT, $this->connectionId, self::DOMAIN, self::ssoClient())->status);

        $linking = $app->make(LinkingPolicyService::class)->change(self::TENANT, $this->connectionId, [
            'enabled'            => true,
            'issuer_class'       => 'shared',
            'organization_claim' => 'hd',
            'organization_value' => self::DOMAIN,
        ], self::ssoClient());

        self::assertTrue($linking->isChanged(), 'The connection\'s linking was not turned on.');
    }

    /**
     * Bind a grant half answering `within_tenant`, standing in for
     * `laravel-authorization`'s grant scope query, so that a test of the
     * memberships alone needs no `laravel-authorization` grants.
     *
     * @return void
     */
    protected function grantsWithin(): void
    {
        $this->app?->instance(GrantScope::class, new readonly class implements GrantScope {
            /**
             * Every identity's grants are within the tenant.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
             * @param  string  $tenantId
             * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
             */
            #[\Override]
            public function judge(Identity $identity, string $tenantId): ScopeVerdict
            {
                return ScopeVerdict::WITHIN_TENANT;
            }
        });
    }

    /**
     * Sign in for the first time by the verified email, the provider asserting
     * the organisation's value, and redeem the code through this package.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    protected function signInByDomain(): SignInResult
    {
        $handoff = $this->handoff(Purpose::SIGN_IN, tailor: self::byDomain());
        $result  = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $result, 'SSO refused the redemption.');

        return $result;
    }

    /**
     * The provider's token carrying the verified email and the organisation's
     * value under `hd`.
     *
     * @return \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken
     */
    protected static function byDomain(): \Closure
    {
        return static fn (FakeIdToken $token): FakeIdToken => $token->with('email', self::EMAIL)->with('email_verified', true)->with('hd', self::DOMAIN);
    }
}
