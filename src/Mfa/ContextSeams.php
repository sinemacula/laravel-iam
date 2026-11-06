<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Context\IdentityContractSubjectType;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Requirements\NoActiveTenant;

/**
 * The seams MFA reads its context through, answered by `laravel-authentication`
 * (IAM-3.12): the event context and the application from the caller, the active
 * tenant from the validated session's tenant, never a request or an event, and
 * the subject type from the machine identity contract.
 *
 * Each binds while MFA's capability switch (`iam.adapters.mfa`) is on, and
 * replaces the member's own default only (IAM-8.4). MFA binds no application
 * resolver of its own, so that seam is replaced only while unbound. Every
 * adapter is transient, and reads the caller or the session afresh on every
 * call (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ContextSeams implements ProvidesSeams
{
    /**
     * Return the bindings of MFA's context, each on while MFA's capability
     * switch is.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on = static fn (Repository $switches): bool => MfaSeams::isOn($switches);

        return [
            new SeamBinding(EventContextResolver::class, EventContextResolverAdapter::class, [DefaultEventContextResolver::class], appliesWhen: $on),
            new SeamBinding(ActiveTenantResolver::class, ActiveTenantResolverAdapter::class, [NoActiveTenant::class], appliesWhen: $on),
            new SeamBinding(SubjectTypeResolver::class, SubjectTypeResolverAdapter::class, [IdentityContractSubjectType::class], appliesWhen: $on),
            new SeamBinding(ApplicationResolver::class, ApplicationResolverAdapter::class, [], appliesWhen: $on),
        ];
    }
}
