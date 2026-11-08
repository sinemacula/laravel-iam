<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Context\IdentityContractActiveState;
use SineMacula\Laravel\Mfa\Context\IdentityContractSubjectType;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Requirements\NoActiveTenant;

/**
 * The seams MFA reads its context through, answered by `laravel-authentication`
 * (IAM-3.12): the event context from the caller, the application from the guard
 * MFA names it through, the active tenant from the validated session's tenant,
 * never a request or an event, the subject type from the machine identity
 * contract, and the active state from its own (`CanBeActive`).
 *
 * Each binds while MFA's capability switch (`iam.adapters.mfa`) is on, and
 * replaces the member's own default only (IAM-8.4). MFA binds no application
 * resolver of its own, so that seam is replaced only while unbound. Every
 * adapter is transient, and reads the caller or the session afresh on every
 * call (IAM-8.1). The active tenant's is mandatory while SSO's enforcement is
 * on or the application names or binds a tenant MFA requirement (IAM-10.2):
 * left on MFA's `NoActiveTenant` then, no tenant's requirement would reach MFA.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ContextSeams implements ProvidesSeams
{
    /**
     * Constructor.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Tells whether the application has bound a tenant MFA requirement, which the active tenant's mandate reads; with none, only the configuration is read. */
        private ?Container $container = null,
    ) {}

    /**
     * Return the bindings of MFA's context, each on while MFA's capability
     * switch is, the active tenant's mandatory while SSO's enforcement or a
     * tenant MFA requirement is on.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on       = static fn (Repository $switches): bool => MfaSeams::isOn($switches);
        $enforced = TenancySeams::isEnforcedOrRequired($config, $this->container);

        return [
            new SeamBinding(EventContextResolver::class, EventContextResolverAdapter::class, [DefaultEventContextResolver::class], appliesWhen: $on),
            new SeamBinding(ActiveTenantResolver::class, ActiveTenantResolverAdapter::class, [NoActiveTenant::class], appliesWhen: $on, mandatory: $enforced),
            new SeamBinding(SubjectTypeResolver::class, SubjectTypeResolverAdapter::class, [IdentityContractSubjectType::class], appliesWhen: $on),
            new SeamBinding(ActiveStateResolver::class, ActiveStateResolverAdapter::class, [IdentityContractActiveState::class], appliesWhen: $on),
            new SeamBinding(ApplicationResolver::class, ApplicationResolverAdapter::class, [], appliesWhen: $on),
        ];
    }
}
