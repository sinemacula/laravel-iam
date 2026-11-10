<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Contracts\Foundation\Application;
use Orchestra\Testbench\Foundation\Application as Testbench;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
use SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Sso\Redemptions;
use Tests\Fixtures\Tenancy\ScriptedEnforcement;

/**
 * Tenant authentication policy benchmark fixtures: an application with every
 * member's provider and this package's, the composite policy as bound, and a
 * sign-in it judges.
 *
 * The policy is asked on every sign-in in a tenant, every activation, every
 * refresh and every switch, sometimes while `laravel-authentication` holds the
 * session's row lock, so its own cost is held while the lock is. With SSO's
 * enforcement off and no tenant MFA requirement it reads nothing and computes
 * the answer's version alone. With a rule and a requirement, it is given SSO's
 * policy and the application's rule in memory (a scripted enforcement and the
 * fake requirement, whose own reads are the members' and the application's),
 * asks the sign-in's connection, which `laravel-authentication` names from the
 * sign-in's evidence in memory, and composes the answer and its version:
 * everything the adapter does itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TenantAuthenticationPolicyBenchHarness
{
    /** @var string The guard the sign-in is on. */
    private const string GUARD = 'api';

    /** @var \Illuminate\Contracts\Foundation\Application The application the policy is resolved from. */
    private Application $app;

    /** @var \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext A sign-in of a person through the redemption's connection. */
    private TenantPolicyContext $signIn;

    /**
     * Build the application and the sign-in, with SSO's enforcement off and no
     * tenant MFA requirement, or with a rule through the redemption's
     * connection and a requirement, both held in memory, and check that the
     * policy bound is the composite adapter.
     *
     * @param  bool  $enforced
     *
     * @throws \LogicException
     */
    public function __construct(bool $enforced = false)
    {
        $this->app = self::application();

        $person = new Person;

        $person->forceFill(['id' => 1]);

        $this->signIn = new TenantPolicyContext(self::GUARD, $person, $person, new ClaimedTenant(Redemptions::TENANT), null, static fn (): string => Redemptions::CONNECTION);

        if ($enforced) {
            $this->enforce();
        }

        if (!$this->policy() instanceof TenantAuthenticationPolicyAdapter) {
            throw new \LogicException('The tenant authentication policy bound is not the composite adapter.');
        }
    }

    /**
     * Answer the sign-in.
     *
     * @return void
     */
    public function answers(): void
    {
        $this->policy()->requirementFor($this->signIn);
    }

    /**
     * Require the sign-in to come through the redemption's connection or
     * another, and multifactor authentication within five minutes.
     *
     * @return void
     */
    private function enforce(): void
    {
        $this->app->instance(Enforcement::class, (new ScriptedEnforcement)->requireThrough([Redemptions::CONNECTION, 'connection-2']));

        FakeTenantMfaRequirement::fake($this->app)->require(Redemptions::TENANT, new Requirement(multifactor: new RequirementPart(300)));
    }

    /**
     * The policy, as `laravel-authentication` resolves it on each call.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy
     */
    private function policy(): TenantAuthenticationPolicy
    {
        return $this->app->make(TenantAuthenticationPolicy::class);
    }

    /**
     * The application, with every member's provider and this package's and its
     * guard declared.
     *
     * @return \Illuminate\Contracts\Foundation\Application
     */
    private static function application(): Application
    {
        $providers = [
            AuthenticationServiceProvider::class,
            AuthorizationServiceProvider::class,
            MfaServiceProvider::class,
            SsoServiceProvider::class,
            AuditLogServiceProvider::class,
            IamServiceProvider::class,
        ];

        $app = Testbench::create(options: ['extra' => ['providers' => $providers, 'dont-discover' => ['*']]]);

        $app->make('config')->set([
            'app.key'                    => 'base64:' . base64_encode(str_repeat('b', 32)),
            'database.default'           => 'bench',
            'database.connections.bench' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => ''],
            'auth.defaults.guard'        => self::GUARD,
            'auth.guards.' . self::GUARD => ['driver' => 'jwt', 'provider' => 'people', 'application' => ['methods' => ['password', 'external_provider']]],
            'auth.providers.people'      => ['driver' => 'model', 'model' => Person::class],
        ]);

        return $app;
    }
}
