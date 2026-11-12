<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * MFA's tenant requirement as a test scripts it, keeping every question asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedTenantRequirement implements TenantRequirement
{
    /** @var array<string, \SineMacula\Laravel\Mfa\Requirements\Requirement> What each tenant requires. */
    private array $requirements = [];

    /** @var array<string, \Throwable> What each tenant's question throws. */
    private array $failures = [];

    /** @var list<array{tenant: string, application: string}> Every question asked, in order. */
    private array $asked = [];

    /**
     * Bind a fresh one as MFA's tenant requirement and return it.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function bind(?ContainerContract $container): self
    {
        $requirement = new self;

        ($container ?? Container::getInstance())->instance(TenantRequirement::class, $requirement);

        return $requirement;
    }

    /**
     * Have the tenant require the requirement from now on.
     *
     * @param  string  $tenantId
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return self
     */
    public function require(string $tenantId, Requirement $requirement): self
    {
        $this->requirements[$tenantId] = $requirement;

        unset($this->failures[$tenantId]);

        return $this;
    }

    /**
     * Have every question about the tenant throw the failure.
     *
     * @param  string  $tenantId
     * @param  \Throwable  $failure
     * @return self
     */
    public function failFor(string $tenantId, \Throwable $failure): self
    {
        $this->failures[$tenantId] = $failure;

        return $this;
    }

    /**
     * What the tenant requires, or the failure the test scripted.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Throwable
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, string $tenant): Requirement
    {
        $this->asked[] = ['tenant' => $tenant, 'application' => $application];

        if (isset($this->failures[$tenant])) {
            throw $this->failures[$tenant];
        }

        return $this->requirements[$tenant] ?? Requirement::none();
    }

    /**
     * Every question asked so far, in order.
     *
     * @return list<array{tenant: string, application: string}>
     */
    public function asked(): array
    {
        return $this->asked;
    }
}
