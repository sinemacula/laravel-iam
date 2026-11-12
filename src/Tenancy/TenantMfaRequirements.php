<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Mfa\Requirements\NoTenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;

/**
 * Asks the application's binding of MFA's tenant requirement on the write
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantMfaRequirements
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator  $translator
     */
    public function __construct(

        /** Resolves MFA's tenant requirement on each call. */
        private Container $container,

        /** Translates its answer to `laravel-authentication`'s. */
        private RequirementTranslator $translator,
    ) {}

    /**
     * Whether MFA's tenant requirement is bound off MFA's default.
     *
     * @return bool
     */
    public function isConfigured(): bool
    {
        return !MfaServiceProvider::isPackageDefault($this->container, TenantRequirement::class);
    }

    /**
     * What the tenant requires of the context's identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext  $context
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function requirementFor(TenantPolicyContext $context, string $tenantId): Requirement
    {
        $requirement = $this->requirement();
        $identity    = $context->identity;

        if ($requirement instanceof NoTenantRequirement) {
            return new Requirement;
        }

        if (!$identity instanceof MultiFactorAuthenticatable) {
            throw UnresolvedReferenceException::forMfaIdentity($identity::class);
        }

        $answer = WriteConnection::during($context->tenant, static fn (): MfaRequirement => $requirement->requirementFor($identity, $context->application, $tenantId));

        return $this->translator->toAuthentication($answer);
    }

    /**
     * MFA's tenant requirement as the container binds it now.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\TenantRequirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function requirement(): TenantRequirement
    {
        return $this->container->make(TenantRequirement::class);
    }
}
