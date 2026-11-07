<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRequirements;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * MFA's tenant requirement, answered from the application's tenant MFA
 * requirement (IAM-4.5, MFA-10.2): the same answer `laravel-authentication`'s
 * tenant authentication policy is given, so the two members never disagree
 * about what a tenant requires.
 *
 * MFA names the active tenant by its opaque id (the one its active tenant
 * resolver read from `laravel-authentication`'s validated session); the id is
 * resolved through `laravel-authentication`'s own tenant resolver
 * (`TenantReferences`), on the write connection, to the tenant of exactly that
 * identifier, and the application's requirement is asked for that tenant and
 * the application, on the write connection too (`TenantMfaRequirements`). Its
 * requirement is translated to MFA's, part by part, each with its maximum age
 * (`RequirementTranslator::toMfa()`); its version is `laravel-authentication`'s
 * concern alone, since MFA works a session's requirement out afresh on every
 * call.
 *
 * The application's requirement answers for the tenant and the application: it
 * is not asked about the identity, since which tenants require what is the
 * tenant's policy, the same for everyone acting in it. It answers for exactly
 * the tenant asked, with no inheritance down a tenant tree applied here. With
 * no requirement bound or named, no tenant requires a further factor, and
 * nothing is resolved or read: an application whose sessions act in tenants its
 * tenant resolver does not know (`laravel-authentication`'s default resolves
 * none) is not refused for a requirement it never asked for. Otherwise a tenant
 * id that resolves to no tenant, or to one of another identifier, throws
 * `UnresolvedReferenceException` (IAM-8.2) inside whatever transaction MFA
 * opened, and so does anything the application's requirement throws: no tenant
 * is answered as requiring nothing because it could not be asked.
 *
 * It only reads and takes no lock. It holds nothing between calls: the resolver
 * and the application's requirement are resolved on every call (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantRequirementAdapter implements TenantRequirement
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenantReferences  $tenants
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenantMfaRequirements  $requirements
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator  $translator
     */
    public function __construct(

        /** Resolves the tenant MFA names by its id. */
        private TenantReferences $tenants,

        /** Asks the application's tenant MFA requirement. */
        private TenantMfaRequirements $requirements,

        /** Translates the requirement to MFA's. */
        private RequirementTranslator $translator,
    ) {}

    /**
     * What the identity's active tenant requires on the application, as MFA's
     * requirement.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenantMfaRequirementMisconfiguredException
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, string $tenant): Requirement
    {
        if (!$this->requirements->isConfigured()) {
            return Requirement::none();
        }

        return $this->translator->toMfa($this->requirements->ruleFor($this->tenants->tenant($tenant), $application)->requirement);
    }
}
