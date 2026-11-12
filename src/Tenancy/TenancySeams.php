<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;

/**
 * The seams SSO and `laravel-authentication` answer from the application's
 * tenancy, switched by `iam.adapters.sso`: the tenant authentication policy
 * (IAM-4.5), mandatory while SSO's enforcement is on or MFA's tenant
 * requirement is bound; SSO's membership seams (IAM-6.8, IAM-7.4), bound only
 * while the application has memberships; and SSO's enforcement inheritance
 * (IAM-7.5), mandatory while enforcing over a tenant tree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenancySeams implements ProvidesSeams
{
    /** @var string SSO's enforcement switch. */
    public const string ENFORCEMENT = 'sso.features.enforcement';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Tells whether the application has bound MFA's tenant requirement, memberships or a tenant tree. */
        private Container $container,
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
        $on          = SsoSeams::isOn($config);
        $memberships = $on && TenancyContracts::hasMemberships($this->container, $config);
        $mandatory   = fn (): bool => self::isEnforcedOrRequired($config, $this->container);
        $inherited   = fn (): bool => self::isEnforced($config) && TenancyContracts::hasTree();

        return [
            new SeamBinding(TenantAuthenticationPolicy::class, TenantAuthenticationPolicyAdapter::class, $on, mandatory: $mandatory),
            new SeamBinding(TenantMembership::class, TenantMembershipAdapter::class, $memberships),
            new SeamBinding(LinkEligibility::class, LinkEligibilityAdapter::class, $memberships),
            new SeamBinding(PrincipalScope::class, PrincipalScopeAdapter::class, $memberships),
            new SeamBinding(EnforcementInheritance::class, EnforcementInheritanceAdapter::class, $on, mandatory: $inherited),
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
