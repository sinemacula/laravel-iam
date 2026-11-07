<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRule;

/**
 * A tenant MFA requirement for tests: each tenant requires what the test told
 * it to (`require()`), nothing until then, and a tenant the test told it to
 * fail for throws (`failFor()`), as an application's requirement that cannot
 * answer does.
 *
 * Every answer is versioned by the tenant and how many times the test changed
 * what it requires, so the version changes whenever the answer does and stays
 * the same while it does not, as `laravel-authentication` needs it to. Each
 * question is kept (`asked()`), so a test can see which tenant and application
 * were asked about.
 *
 * Call `FakeTenantMfaRequirement::fake()`, which binds a fresh instance as the
 * application's requirement and returns it; a requirement bound in the
 * container counts as named in `iam.tenancy.mfa_requirement`. Change a tenant's
 * requirement before the sessions it concerns are judged, or report the change
 * for the tenant after (`Iam::tenantPolicies()->changed()`), as the application
 * would. It satisfies this package's own
 * `Seams\Concerns\TenantMfaRequirementTests` kit. Not for production use.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeTenantMfaRequirement implements TenantMfaRequirement
{
    /** @var class-string The contract the fake is bound as. */
    public const string REQUIREMENT = TenantMfaRequirement::class;

    /** @var string What every version the fake answers starts with. */
    private const string VERSION_PREFIX = 'fake:';

    /** @var array<string, \SineMacula\Laravel\Authentication\Requirements\Requirement> What each tenant requires, by its id. */
    private array $requirements = [];

    /** @var array<string, int> How many times each tenant's requirement was changed, by its id. */
    private array $changes = [];

    /** @var array<string, \Throwable> What asking about each tenant throws, by its id. */
    private array $failures = [];

    /** @var list<array{tenant: string, application: string}> Every question asked, in order. */
    private array $asked = [];

    /**
     * Bind a fresh fake as the application's tenant MFA requirement in the
     * container given, or the application's own, and return it.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function fake(?ContainerContract $container = null): self
    {
        $fake = new self;

        ($container ?? Container::getInstance())->instance(self::REQUIREMENT, $fake);

        return $fake;
    }

    /**
     * Have the tenant require the requirement of every session acting in it, on
     * every application, from now on.
     *
     * @param  string  $tenantId
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return self
     */
    public function require(string $tenantId, Requirement $requirement): self
    {
        $this->requirements[$tenantId] = $requirement;
        $this->changes[$tenantId]      = ($this->changes[$tenantId] ?? 0) + 1;

        unset($this->failures[$tenantId]);

        return $this;
    }

    /**
     * Have the tenant require nothing from now on.
     *
     * @param  string  $tenantId
     * @return self
     */
    public function requireNothing(string $tenantId): self
    {
        return $this->require($tenantId, new Requirement);
    }

    /**
     * Have every question about the tenant throw, as an application's
     * requirement that cannot answer for it does, until the test changes what
     * it requires.
     *
     * @param  string  $tenantId
     * @param  ?\Throwable  $failure
     * @return self
     */
    public function failFor(string $tenantId, ?\Throwable $failure = null): self
    {
        $this->failures[$tenantId] = $failure ?? new \RuntimeException(sprintf('The fake tenant MFA requirement cannot answer for the tenant [%s].', $tenantId));

        return $this;
    }

    /**
     * What the tenant requires, versioned by the tenant and how many times its
     * requirement was changed, or the failure the test told it to throw.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $application
     * @return \SineMacula\Laravel\Iam\Tenancy\TenantMfaRule
     *
     * @throws \Throwable
     */
    #[\Override]
    public function requirementFor(Tenant $tenant, string $application): TenantMfaRule
    {
        $tenantId = IdentifierCoercion::stringify($tenant->getTenantIdentifier()) ?? throw self::unidentified();

        $this->asked[] = ['tenant' => $tenantId, 'application' => $application];

        if (isset($this->failures[$tenantId])) {
            throw $this->failures[$tenantId];
        }

        $version = sprintf('%s%s:%d', self::VERSION_PREFIX, hash('xxh128', $tenantId), $this->changes[$tenantId] ?? 0);

        return new TenantMfaRule($this->requirements[$tenantId] ?? new Requirement, $version);
    }

    /**
     * Every question asked so far, in order: the tenant's id and the
     * application.
     *
     * @return list<array{tenant: string, application: string}>
     */
    public function asked(): array
    {
        return $this->asked;
    }

    /**
     * The refusal of a tenant identified by neither a string nor an integer,
     * which the fake cannot key its answers by.
     *
     * @return \InvalidArgumentException
     */
    private static function unidentified(): \InvalidArgumentException
    {
        return new \InvalidArgumentException('The fake tenant MFA requirement answers for a tenant identified by a string or an integer.');
    }
}
