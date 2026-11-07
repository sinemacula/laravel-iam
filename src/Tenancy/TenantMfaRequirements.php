<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Exceptions\TenantMfaRequirementMisconfiguredException;

/**
 * Asks the application's tenant MFA requirement what a tenant requires
 * (IAM-4.5), the one answer both MFA's tenant requirement and
 * `laravel-authentication`'s tenant authentication policy are given.
 *
 * The requirement is the application's binding of
 * `Contracts\TenantMfaRequirement`, when there is one (IAM-8.4), and otherwise
 * the class `iam.tenancy.mfa_requirement` names, which must implement it;
 * either is resolved from the container on every call, so whatever the
 * application binds, whenever it binds it, is the one asked, and nothing is
 * kept between calls (IAM-8.1). With neither, no tenant requires a further
 * factor: that is the application's choice, made by naming none (`null`, or
 * blank text). A class named that is no requirement, a value that is no class
 * name at all (`true`, `false`, a number, an array), or a binding that resolves
 * to no requirement, fails closed rather than answer that nothing is required.
 *
 * The requirement is asked inside `WriteConnection::during()` for the tenant,
 * as `laravel-authentication` asks its own tenant policy, so a model read it
 * makes is pinned to the write connection: a replica that has not yet seen a
 * changed requirement never answers for it. MFA asks its own tenant requirement
 * outside any such pin, so the pin is this class's, not left to the member that
 * asks. Whatever it throws propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantMfaRequirements
{
    /** @var string The configuration key naming the application's tenant MFA requirement. */
    public const string KEY = 'iam.tenancy.mfa_requirement';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container the application's requirement is bound or built in. */
        private Container $container,

        /** The configuration naming the application's requirement. */
        private Repository $config,
    ) {}

    /**
     * What the tenant requires of a session acting in it on the application, as
     * the application answers.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $application
     * @return \SineMacula\Laravel\Iam\Tenancy\TenantMfaRule
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenantMfaRequirementMisconfiguredException
     */
    public function ruleFor(Tenant $tenant, string $application): TenantMfaRule
    {
        $requirement = $this->requirement();

        return $requirement === null
            ? TenantMfaRule::none()
            : WriteConnection::during($tenant, static fn (): TenantMfaRule => $requirement->requirementFor($tenant, $application));
    }

    /**
     * Whether the application has a tenant MFA requirement: one bound in the
     * container, or a class named for it. Without one, no tenant requires a
     * further factor, so nothing about a tenant need be resolved to answer.
     *
     * @return bool
     */
    public function isConfigured(): bool
    {
        return $this->container->bound(TenantMfaRequirement::class) || self::isNamed($this->config);
    }

    /**
     * Whether the configuration names anything for the application's tenant MFA
     * requirement: any value but `null` and blank text, which alone name none.
     * Whether what it names is a requirement is `ruleFor()`'s to check, and
     * fails closed there: a value that is no text (`true`, `false`, a number,
     * an array) is a misconfiguration, never a choice of no requirement.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function isNamed(Repository $config): bool
    {
        $class = $config->get(self::KEY);

        return $class !== null && (!is_string($class) || trim($class) !== '');
    }

    /**
     * The application's requirement, as bound or as named, or `null` when it
     * has neither.
     *
     * @return ?\SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenantMfaRequirementMisconfiguredException
     */
    private function requirement(): ?TenantMfaRequirement
    {
        if ($this->container->bound(TenantMfaRequirement::class)) {
            return $this->resolved(TenantMfaRequirement::class);
        }

        if (!self::isNamed($this->config)) {
            return null;
        }

        $named = $this->config->get(self::KEY);

        if (!is_string($named)) {
            throw TenantMfaRequirementMisconfiguredException::forValue(self::KEY, get_debug_type($named), TenantMfaRequirement::class);
        }

        if (!is_subclass_of($named, TenantMfaRequirement::class)) {
            throw TenantMfaRequirementMisconfiguredException::forClass(self::KEY, $named, TenantMfaRequirement::class);
        }

        return $this->resolved($named);
    }

    /**
     * Build the requirement the container resolves by the abstract given, which
     * must implement the contract.
     *
     * @param  string  $abstract
     * @return \SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenantMfaRequirementMisconfiguredException
     */
    private function resolved(string $abstract): TenantMfaRequirement
    {
        $requirement = $this->container->make($abstract);

        return $requirement instanceof TenantMfaRequirement
            ? $requirement
            : throw TenantMfaRequirementMisconfiguredException::forBinding($abstract, get_debug_type($requirement), TenantMfaRequirement::class);
    }
}
