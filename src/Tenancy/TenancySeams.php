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
 * composed of SSO's enforcement and exemption gate and the application's tenant
 * MFA requirement (`TenantAuthenticationPolicyAdapter`), over
 * `laravel-authentication`'s default, `RequireNothingOfTenants`.
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
 * The seams SSO answers from the application's memberships and tenant tree
 * (IAM-6.8, IAM-7.4, IAM-7.5) are declared here too, each on while the SSO
 * capability's switch is, since each is SSO's:
 *
 * - SSO's `TenantMembership`, `LinkEligibility` and `PrincipalScope`, answered
 *   from the application's memberships (`TenantMembershipAdapter`,
 *   `LinkEligibilityAdapter`, `PrincipalScopeAdapter`), only while the
 *   application names memberships in `iam.tenancy.memberships` or binds
 *   `Contracts\Memberships` by the time every provider has registered (in an
 *   application provider's `register()`, say). Without them SSO's defaults
 *   stay, and refuse: no membership, no link, a scope `unknown`; no adapter is
 *   bound that would have to invent an answer.
 * - SSO's `EnforcementInheritance`, answered from the application's tenant tree
 *   (`EnforcementInheritanceAdapter`), only while the application names a tree
 *   in `iam.tenancy.tree` or binds `Contracts\TenantTree` by the time every
 *   provider has registered. Without one SSO's default stays, and each tenant's
 *   rule applies to it alone.
 *
 * Laravel registers the application's own providers after the packages', so a
 * binding made in an application provider's `register()` comes after this
 * package's binding rule has run: these rows are applied once more once every
 * provider has registered, from this package's booting callback
 * (`BindingRule::applyAgain()`). As the rule first runs, each row it leaves off
 * is reserved (`BindingRule::reserve()`): the exact binding of SSO's default
 * the seam holds is recorded, SSO's default bound there first, shared, as SSO
 * binds it, where SSO has not registered yet. Applied again, a row is bound
 * only over that very binding, so an application's own binding of SSO's seam
 * made by then is still kept, even one of SSO's own default class, made to keep
 * each tenant's rule to itself while the application keeps a tree for its own
 * requirements and for the tree changes, say. These rows follow the SSO
 * capability's switch as it read when this package registered, as SSO's other
 * seams did, so they and those seams are bound together or not at all: a value
 * a later provider writes comes too late for either, off as much as on. None of
 * these is mandatory: SSO's defaults fail closed, and a tree is the
 * application's choice. A membership contract or a tree bound from a provider's
 * `boot()` binds none of these adapters, though the revocations and the
 * adapters that are bound still ask it.
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
    /** @var string SSO's switch for its enforcement, which the binding is mandatory while on. */
    public const string ENFORCEMENT = 'sso.features.enforcement';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  bool|null  $ssoOn
     */
    public function __construct(

        /** Tells whether the application has bound a tenant MFA requirement, memberships or a tenant tree. */
        private Container $container,

        /** The SSO capability's switch as it read when this package registered, which the rows answered from the memberships and the tree follow; `null` reads it from the switches each row is given. */
        private ?bool $ssoOn = null,
    ) {}

    /**
     * Return the tenant authentication policy's binding, on while the SSO
     * capability's switch is, and mandatory while SSO's enforcement or a tenant
     * MFA requirement is; and the bindings answered from the application's
     * memberships and tenant tree, each on while the switch is and the
     * application has the one it answers from.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on          = SsoSeams::isOn(...);
        $mandatory   = $this->isMandatory($config);
        $memberships = fn (Repository $switches): bool => $this->isSsoOn($switches) && TenancyContracts::hasMemberships($this->container, $switches);
        $tree        = fn (Repository $switches): bool => $this->isSsoOn($switches) && TenancyContracts::hasTree($this->container, $switches);

        return [
            new SeamBinding(TenantAuthenticationPolicy::class, TenantAuthenticationPolicyAdapter::class, [RequireNothingOfTenants::class], appliesWhen: $on, mandatory: $mandatory),
            new SeamBinding(TenantMembership::class, TenantMembershipAdapter::class, [NoTenantMembership::class], appliesWhen: $memberships),
            new SeamBinding(LinkEligibility::class, LinkEligibilityAdapter::class, [RefusingLinkEligibility::class], appliesWhen: $memberships),
            new SeamBinding(PrincipalScope::class, PrincipalScopeAdapter::class, [RefusingPrincipalScope::class], appliesWhen: $memberships),
            new SeamBinding(EnforcementInheritance::class, EnforcementInheritanceAdapter::class, [OwnTenantInheritance::class], appliesWhen: $tree),
        ];
    }

    /**
     * Whether the SSO capability's switch is on for the rows answered from the
     * memberships and the tree: as it read when this package registered, when
     * this was given it, so the rows applied again once every provider has
     * registered are bound with SSO's other seams or not at all, whatever a
     * later provider wrote; otherwise as the switches read it.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $switches
     * @return bool
     */
    private function isSsoOn(Repository $switches): bool
    {
        return $this->ssoOn ?? SsoSeams::isOn($switches);
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
