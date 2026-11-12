<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;

/**
 * The seams SSO and `laravel-authentication` answer from the application's
 * tenancy, switched by `iam.adapters.sso`.
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
     * The tenant authentication policy and SSO's tenancy seams.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on          = SsoSeams::isOn($config);
        $memberships = $on && $this->container->bound(Memberships::class);
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
     * Whether SSO's enforcement is on or MFA's tenant requirement is bound.
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
     * Whether SSO's enforcement switch is on.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    private static function isEnforced(Repository $config): bool
    {
        return filter_var($config->get(self::ENFORCEMENT), FILTER_VALIDATE_BOOL);
    }
}
