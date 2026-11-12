<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * Checks the configuration that spans authentication, MFA, SSO and
 * authorization.
 *
 * Every MFA application is a `jwt` guard; MFA's and SSO's operations are
 * declared in each guard's freshness; the tenant resolver is bound off its
 * default wherever a member resolves tenants; and a default resource tenant
 * resolver is noted while people act in tenants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CrossMemberConfigurationCheck implements Check
{
    /** @var string The key of the application's guards. */
    private const string GUARDS = 'auth.guards';

    /** @var string The key of MFA's applications. */
    private const string MFA_APPLICATIONS = 'mfa.applications';

    /** @var string The key of SSO's applications. */
    private const string SSO_APPLICATIONS = 'sso.applications';

    /** @var string The key of laravel-authentication's freshness operations. */
    private const string FRESHNESS = 'authentication.freshness';

    /** @var string The failure for an MFA application naming no guard. */
    private const string NO_GUARD = '`%s.%s` names no guard in `%s`: MFA\'s application is the guard of the same name.';

    /** @var string The failure for an MFA application on a guard of another driver. */
    private const string NOT_SESSION_GUARD = '`%s.%s` names a guard in `%s` whose driver is not `jwt`: MFA\'s application is a guard that holds sessions.';

    /** @var string The failure for a tenant resolver still on its default. */
    private const string NO_TENANT_RESOLVER = '%s is still bound to %s while SSO\'s enforcement is on, MFA\'s tenant requirement is bound,'
        . ' laravel-authorization\'s grants are reported to SSO\'s scope widening, or laravel-authorization reads the tenant tree:'
        . ' bind a resolver that resolves every tenant id'
        . ' to the tenant whose `getTenantIdentifier()` is that id.';

    /** @var string The key naming laravel-authorization's resource tenant resolver. */
    private const string RESOURCE_TENANTS = 'authorization.resource_tenant_resolver';

    /** @var string The note for a resource tenant resolver still on its default. */
    private const string NO_RESOURCE_TENANTS = '%s is still %s while people act in tenants: no record is refused for its tenant unless its model declares its tenancy'
        . ' (QueryableResource) or names its tenant (AuthorizableResource); name a resolver in `%s`, or bind %s.';

    /** @var string The failure for operations a guard's freshness does not declare. */
    private const string UNDECLARED = '%s\'s freshness operations [%s] are not declared for guard [%s] under `%s` or the guard\'s `freshness`.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Container\Container  $container
     */
    public function __construct(

        /** The configuration every member's settings are read from. */
        private Repository $config,

        /** The container the resolvers and MFA's tenant requirement are bound in. */
        private Container $container,
    ) {}

    /**
     * The subject the findings are reported under.
     *
     * @return string
     */
    #[\Override]
    public function subject(): string
    {
        return 'configuration';
    }

    /**
     * The check always applies.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * The tenant resolvers, then each MFA application's guard and freshness,
     * then SSO's.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $checks = $this->resolvesTenants() ? [fn () => $this->assertTenantsResolve()] : [];

        if ($this->container->bound(Memberships::class)) {
            $checks[] = fn (): ?string => $this->resourceTenantsNote();
        }

        foreach (self::names($this->config->get(self::MFA_APPLICATIONS)) as $application) {
            $checks[] = fn () => $this->assertGuard($application);
            $checks[] = fn () => $this->assertDeclared($application, array_column(Operation::cases(), 'value'), 'MFA');
        }

        $ssoApplications = SsoSeams::isInUse($this->config) ? self::names($this->config->get(self::SSO_APPLICATIONS)) : [];

        foreach ($ssoApplications as $application) {
            $checks[] = fn () => $this->assertDeclared($application, array_column(FreshnessOperation::cases(), 'value'), 'SSO');
        }

        return $checks;
    }

    /**
     * Whether a member resolves tenants through laravel-authentication's
     * resolver.
     *
     * @return bool
     */
    private function resolvesTenants(): bool
    {
        return TenancySeams::isEnforcedOrRequired($this->config, $this->container)
            || AuthorizationSeams::reportsWidenings($this->config)
            || TenancyContracts::hasTree();
    }

    /**
     * Refuse a tenant resolver still on laravel-authentication's default.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertTenantsResolve(): void
    {
        if (!AuthenticationServiceProvider::isPackageDefault($this->container, TenantResolver::class)) {
            return;
        }

        throw new \LogicException(sprintf(self::NO_TENANT_RESOLVER, TenantResolver::class, ResolveNoTenant::class));
    }

    /**
     * A note while the resource tenant resolver is still on its default.
     *
     * @return ?string
     */
    private function resourceTenantsNote(): ?string
    {
        if (!AuthorizationServiceProvider::isPackageDefault($this->container, ResourceTenantResolver::class)) {
            return null;
        }

        return sprintf(self::NO_RESOURCE_TENANTS, ResourceTenantResolver::class, NoResourceTenant::class, self::RESOURCE_TENANTS, ResourceTenantResolver::class);
    }

    /**
     * Refuse an MFA application that names no `jwt` guard.
     *
     * @param  string  $application
     * @return void
     *
     * @throws \LogicException
     */
    private function assertGuard(string $application): void
    {
        if (in_array($application, Auth::sessionGuards(), true)) {
            return;
        }

        $reason = is_array($this->config->get(self::GUARDS . '.' . $application)) ? self::NOT_SESSION_GUARD : self::NO_GUARD;

        throw new \LogicException(sprintf($reason, self::MFA_APPLICATIONS, $application, self::GUARDS));
    }

    /**
     * Refuse a member's operations the guard's freshness does not declare.
     *
     * @param  string  $guard
     * @param  list<string>  $operations
     * @param  string  $member
     * @return void
     *
     * @throws \LogicException
     */
    private function assertDeclared(string $guard, array $operations, string $member): void
    {
        $declared = $this->declared($guard);
        $missing  = array_filter($operations, static fn (string $operation): bool => !array_key_exists($operation, $declared));

        if ($missing === []) {
            return;
        }

        throw new \LogicException(sprintf(self::UNDECLARED, $member, implode(', ', $missing), $guard, self::FRESHNESS));
    }

    /**
     * The guard's declared operations by name; `null` in its own block removes
     * one.
     *
     * @param  string  $guard
     * @return array<array-key, mixed>
     */
    private function declared(string $guard): array
    {
        $global    = $this->config->get(self::FRESHNESS);
        $overrides = $this->config->get(self::GUARDS . '.' . $guard . '.freshness');
        $merged    = array_replace(is_array($global) ? $global : [], is_array($overrides) ? $overrides : []);

        return array_filter($merged, static fn (mixed $entry): bool => $entry !== null);
    }

    /**
     * The keys of an applications map, or none when it is no map.
     *
     * @param  mixed  $applications
     * @return list<string>
     */
    private static function names(mixed $applications): array
    {
        return is_array($applications) ? array_map(strval(...), array_keys($applications)) : [];
    }
}
