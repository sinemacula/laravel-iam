<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
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
 * The configuration that crosses `laravel-authentication`, MFA, SSO and
 * `laravel-authorization` holds (IAM-2.5), at deploy.
 *
 * - MFA's applications are `laravel-authentication`'s guards: every key of
 *   `mfa.applications` names a guard in `auth.guards` of the `jwt` driver,
 *   since MFA's application is the guard of the same name (IAM-3.12) and only a
 *   `jwt` guard holds sessions, so an application on a guard of another driver
 *   is refused at deploy rather than by every MFA call at runtime
 *   (`Mfa\CurrentSession`). A guard with no MFA application is the
 *   application's choice, and enables no factor.
 * - Every operation MFA names (`Mfa\Enums\Operation`) is declared under
 *   `laravel-authentication`'s freshness configuration for each MFA
 *   application's guard, and, while SSO is in use, every operation SSO names
 *   (`Freshness\Enums\FreshnessOperation`) for each SSO application's guard: in
 *   `authentication.freshness`, or in the guard's own `freshness` block, where
 *   `null` removes one. Operations are read as array keys, never as
 *   configuration paths, since their names hold dots.
 * - `laravel-authentication`'s tenant resolver resolves tenants while SSO's
 *   enforcement is on, the application binds MFA's tenant requirement,
 *   `laravel-authorization`'s grants are reported to SSO's scope widening (both
 *   capabilities' switches on, as they are by default,
 *   `AuthorizationSeams::reportsWidenings()`), or the application binds a
 *   tenant tree to `laravel-authorization`: the tenant policy, the tree's
 *   changes, SSO's enforcement inheritance and revocation resolve the session's
 *   tenant through it, and the grant hook every tenant a widening grant holds
 *   in (`Tenancy\TenantReferences`), while `laravel-authentication` admits a
 *   principal's own tenant without one, so an application that never needed a
 *   resolver would otherwise refuse every grant to an identity, or a
 *   principal's first, in a tenant, and every move of a tenant, at runtime. A
 *   resolver still on `laravel-authentication`'s default, as it says, is
 *   refused.
 * - While the application has memberships, so its people act in tenants,
 *   `laravel-authorization`'s resource tenant resolver still on its default is
 *   noted, never failed: the shipped `NoResourceTenant` knows no model's
 *   tenant, so a grant in one tenant reaches another tenant's records unless
 *   each model declares its tenancy (`QueryableResource`) or names its tenant
 *   (`AuthorizableResource`), which no check can see without the application's
 *   models. Which tenant owns a record is the application's answer, never this
 *   package's (IAM-1.2), so nothing here binds one. Whether it is still the
 *   default is `laravel-authorization`'s own answer
 *   (`AuthorizationServiceProvider::isPackageDefault()`).
 *
 * The rest of IAM-2.5 is checked where it belongs, each bullet once: SSO's
 * applications and their unlinked handoffs by `Sso\SsoBridgeCheck`;
 * `sso.endpoints.base_url` by SSO's own `EndpointsCheck`;
 * `sso.storage.connection` by the storage alignment, at boot and in
 * `StorageCheck`; audit-log's exclusions, Gate capture and `require_registered`
 * by `AuditCheck`. `laravel-authorization`'s seams are bound through the
 * container (`Authorization\AuthorizationSeams`), not named in its
 * configuration, so none of its resolver keys is required to name an adapter.
 * Whether a provider attribute lies beyond SSO's standard mapping depends on
 * each connection's mapping, which is a database row, so it is left to the
 * guide, as SSO's routes are.
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

    /** @var string The key of `laravel-authentication`'s freshness operations. */
    private const string FRESHNESS = 'authentication.freshness';

    /** @var string The guard driver whose guards hold sessions, the one MFA's applications are. */
    private const string SESSION_DRIVER = 'jwt';

    /** @var string Why an MFA application naming no guard is refused. */
    private const string NO_GUARD = '`%s.%s` names no guard in `%s`: MFA\'s application is the guard of the same name.';

    /** @var string Why an MFA application naming a guard of another driver is refused. */
    private const string NOT_SESSION_GUARD = '`%s.%s` names a guard in `%s` whose driver is not `%s`: MFA\'s application is a guard that holds sessions.';

    /** @var string Why a tenant resolver still on `laravel-authentication`'s default is refused. */
    private const string NO_TENANT_RESOLVER = '%s is still bound to %s while SSO\'s enforcement is on, MFA\'s tenant requirement is bound,'
        . ' laravel-authorization\'s grants are reported to SSO\'s scope widening, or laravel-authorization reads the tenant tree:'
        . ' bind a resolver that resolves every tenant id'
        . ' to the tenant whose `getTenantIdentifier()` is that id.';

    /** @var string The key of `laravel-authorization`'s configuration naming its resource tenant resolver, which the note names. */
    private const string RESOURCE_TENANTS = 'authorization.resource_tenant_resolver';

    /** @var string The note of a resource tenant resolver still on `laravel-authorization`'s default while people act in tenants. */
    private const string NO_RESOURCE_TENANTS = '%s is still %s while people act in tenants: no record is refused for its tenant unless its model declares its tenancy'
        . ' (QueryableResource) or names its tenant (AuthorizableResource); name a resolver in `%s`, or bind %s.';

    /** @var string Why a member's operations the guard's freshness does not declare are refused. */
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

        /** The container the tenant resolver and MFA's tenant requirement are bound in. */
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
     * The check always applies: an application with no MFA application and SSO
     * out of use is checked for nothing.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * The tenant resolver while a tenant's rule reaches a session, a grant is
     * reported to SSO's scope widening or `laravel-authorization` reads the
     * application's tree, the resource tenant resolver while the application
     * has memberships, every MFA application a guard, then the freshness
     * operations of MFA's applications and, while SSO is in use, of SSO's.
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
     * Whether a member resolves tenants through `laravel-authentication`'s
     * tenant resolver: while a tenant's rule reaches a session, a grant is
     * reported to SSO's scope widening, or `laravel-authorization` reads the
     * application's tenant tree.
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
     * Refuse a tenant resolver still on `laravel-authentication`'s default,
     * `ResolveNoTenant`, which resolves no tenant.
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
     * The note of `laravel-authorization`'s resource tenant resolver left on
     * its default, as `laravel-authorization` says, or nothing once the
     * application names or binds another.
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
     * Refuse an MFA application that names no guard, or a guard of a driver
     * other than `jwt`, which holds no session for MFA to act on.
     *
     * @param  string  $application
     * @return void
     *
     * @throws \LogicException
     */
    private function assertGuard(string $application): void
    {
        $guard = $this->config->get(self::GUARDS . '.' . $application);

        if (!is_array($guard)) {
            throw new \LogicException(sprintf(self::NO_GUARD, self::MFA_APPLICATIONS, $application, self::GUARDS));
        }

        if (($guard['driver'] ?? null) === self::SESSION_DRIVER) {
            return;
        }

        throw new \LogicException(sprintf(self::NOT_SESSION_GUARD, self::MFA_APPLICATIONS, $application, self::GUARDS, self::SESSION_DRIVER));
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
     * The operations declared for the guard, keyed by name:
     * `laravel-authentication`'s, with the guard's own block over them, where
     * `null` removes one.
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
     * The application names a map of applications keys, none when it is no map.
     *
     * @param  mixed  $applications
     * @return list<string>
     */
    private static function names(mixed $applications): array
    {
        return is_array($applications) ? array_map(strval(...), array_keys($applications)) : [];
    }
}
