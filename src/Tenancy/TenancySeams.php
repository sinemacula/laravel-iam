<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Enforcement\OwnTenantInheritance;
use SineMacula\Laravel\Sso\Linking\NoTenantMembership;
use SineMacula\Laravel\Sso\Linking\RefusingLinkEligibility;
use SineMacula\Laravel\Sso\Linking\RefusingPrincipalScope;

/**
 * The seams SSO and `laravel-authentication` answer from the application's
 * tenancy. First, the seam the tenants' authentication policy is answered
 * through (IAM-4.5): `laravel-authentication`'s tenant authentication policy,
 * composed of SSO's enforcement and exemption gate and the application's MFA
 * tenant requirement (`TenantAuthenticationPolicyAdapter`), over
 * `laravel-authentication`'s default, `RequireNothingOfTenants`.
 *
 * It composes SSO's enforcement and MFA's tenant requirement, so it is declared
 * apart from either capability. It is bound while the SSO capability's switch
 * is on (`iam.adapters.sso`), whatever MFA's: it composes SSO's enforcement and
 * exemption gate, and hands the gate the client of the redemption this
 * package's SSO capability admitted in the request (`AdmittedRedemptions`),
 * which nothing records with that capability off. With `iam.adapters.sso` off,
 * the application binds it itself, beside the SSO seams it binds. It is bound
 * whatever SSO's enforcement and the requirement say, since either may be
 * turned on while the application runs, and with neither on it requires nothing
 * and reads nothing, as the default does, answering a version of its own. It is
 * mandatory while SSO's `enforcement` feature is on or the application binds
 * MFA's tenant requirement, whoever binds it: left on the default then, no
 * tenant's enforcement or requirement would reach a session.
 *
 * SSO's `TenantMembership`, `LinkEligibility` and `PrincipalScope` are answered
 * from the application's memberships (IAM-6.8, IAM-7.4), only while it names or
 * binds them by the time every provider has registered; these rows are applied
 * once more then (`BindingRule::applyAgain()`), over the bindings of SSO's
 * defaults reserved as the rule first ran. Without memberships SSO's defaults
 * stay, and refuse.
 *
 * SSO's `EnforcementInheritance` is answered from `laravel-authorization`'s
 * tenant tree (IAM-7.5, `EnforcementInheritanceAdapter`), mandatory while the
 * tree is the application's and SSO's enforcement is on (IAM-10.2).
 *
 * Each adapter replaces the member's own default only; an application's binding
 * is kept (IAM-8.4). The adapters keep nothing and resolve what they ask on
 * every call, so each is transient.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenancySeams implements ProvidesSeams
{
    /** @var string SSO's switch for its enforcement, which the policy's binding, and the inheritance's while the application has a tree, are mandatory while on. */
    public const string ENFORCEMENT = 'sso.features.enforcement';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  bool|null  $ssoOn
     */
    public function __construct(

        /** Tells whether the application has bound MFA's tenant requirement, memberships or a tenant tree. */
        private Container $container,

        /** The SSO capability's switch as it read when this package registered, which the rows answered from the memberships follow; `null` reads it from the switches each row is given. */
        private ?bool $ssoOn = null,
    ) {}

    /**
     * Return the tenant authentication policy's binding and SSO's seams
     * answered from the application's tenancy.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on          = SsoSeams::isOn(...);
        $mandatory   = fn (): bool => self::isEnforcedOrRequired($config, $this->container);
        $inherited   = fn (): bool => self::isEnforced($config) && TenancyContracts::hasTree();
        $memberships = fn (Repository $switches): bool => $this->isSsoOn($switches) && TenancyContracts::hasMemberships($this->container, $switches);

        return [
            new SeamBinding(TenantAuthenticationPolicy::class, TenantAuthenticationPolicyAdapter::class, [RequireNothingOfTenants::class], appliesWhen: $on, mandatory: $mandatory),
            new SeamBinding(TenantMembership::class, TenantMembershipAdapter::class, [NoTenantMembership::class], appliesWhen: $memberships),
            new SeamBinding(LinkEligibility::class, LinkEligibilityAdapter::class, [RefusingLinkEligibility::class], appliesWhen: $memberships),
            new SeamBinding(PrincipalScope::class, PrincipalScopeAdapter::class, [RefusingPrincipalScope::class], appliesWhen: $memberships),
            new SeamBinding(EnforcementInheritance::class, EnforcementInheritanceAdapter::class, [OwnTenantInheritance::class], appliesWhen: $on, mandatory: $inherited),
        ];
    }

    /**
     * Whether SSO's enforcement is on or MFA's tenant requirement is bound off
     * MFA's default; with no container, only the former.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function isEnforcedOrRequired(Repository $config, ?Container $container): bool
    {
        return self::isEnforced($config) || ($container?->make(TenantMfaRequirements::class)->isConfigured() ?? false);
    }

    /**
     * Whether the SSO capability's switch is on for the rows answered from the
     * memberships: as it read when this package registered, when this was given
     * it; otherwise as the switches read it.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $switches
     * @return bool
     */
    private function isSsoOn(Repository $switches): bool
    {
        return $this->ssoOn ?? SsoSeams::isOn($switches);
    }

    /**
     * Whether SSO's enforcement is on, read as SSO would read its own switch to
     * turn it on.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    private static function isEnforced(Repository $config): bool
    {
        return filter_var($config->get(self::ENFORCEMENT), FILTER_VALIDATE_BOOL);
    }
}
