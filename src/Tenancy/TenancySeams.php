<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Sso\SsoSeams;

/**
 * The seam the tenants' authentication policy is answered through (IAM-4.5):
 * `laravel-authentication`'s tenant authentication policy, composed of SSO's
 * enforcement and exemption gate and the application's tenant MFA requirement
 * (`TenantAuthenticationPolicyAdapter`), over `laravel-authentication`'s
 * default, `RequireNothingOfTenants`.
 *
 * It is the one answer for both of its sources, SSO's enforcement and the
 * tenant MFA requirement MFA is given the same answer of, so it is declared
 * apart from either capability. It is bound while the SSO capability's switch
 * is on (`iam.adapters.sso`), whatever MFA's: a sign-in, whose session is not
 * written yet, is established through the connection of the redemption this
 * package's SSO capability admitted in the request (`AdmittedRedemptions`),
 * which nothing records with that capability off, so the adapter would take
 * every SSO sign-in for one through no connection and ask SSO's exemption gate
 * of a compliant one. With `iam.adapters.sso` off, the application binds it
 * itself, beside the SSO seams it binds. It is bound whatever SSO's enforcement
 * and the requirement say, since either may be turned on while the application
 * runs, and with neither on it requires nothing and reads nothing, as the
 * default does, answering a version of its own. It is mandatory while SSO's
 * `enforcement` feature is on or the application names or binds a tenant MFA
 * requirement, whoever binds it: left on the default then, no tenant's
 * enforcement or requirement would reach a session.
 *
 * It replaces the member's own default only; an application's binding is kept
 * (IAM-8.4). The adapter keeps nothing and resolves what it asks on every call,
 * so it is transient.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenancySeams implements ProvidesSeams
{
    /** @var string SSO's switch for its enforcement, which the binding is mandatory while on. */
    public const string ENFORCEMENT = 'sso.features.enforcement';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Tells whether the application has bound a tenant MFA requirement. */
        private Container $container,
    ) {}

    /**
     * Return the tenant authentication policy's binding, on while the SSO
     * capability's switch is, and mandatory while SSO's enforcement or a tenant
     * MFA requirement is.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on        = SsoSeams::isOn(...);
        $mandatory = $this->isMandatory($config);

        return [
            new SeamBinding(TenantAuthenticationPolicy::class, TenantAuthenticationPolicyAdapter::class, [RequireNothingOfTenants::class], appliesWhen: $on, mandatory: $mandatory),
        ];
    }

    /**
     * Whether the tenant authentication policy must be bound off the default:
     * SSO's enforcement is on, read as SSO reads its own switch would turn it
     * on, or the application names or binds a tenant MFA requirement.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    private function isMandatory(Repository $config): bool
    {
        return filter_var($config->get(self::ENFORCEMENT), FILTER_VALIDATE_BOOL)
            || TenantMfaRequirements::isNamed($config)
            || $this->container->bound(TenantMfaRequirement::class);
    }
}
