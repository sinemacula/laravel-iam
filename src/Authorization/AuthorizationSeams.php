<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Sso\SsoSeams;

/**
 * The seams `laravel-authorization` joins the other members through (IAM-6.1 to
 * IAM-6.8, IAM-6.10), switched by `iam.adapters.authorization`. The requirement
 * checker also needs the MFA capability, and the grant hook the SSO capability.
 * Each adapter bound over one of `laravel-authorization`'s contracts is
 * declared to its configuration report, so `authorization:check` names it. The
 * subject resolver and application access are scoped: the resolver because
 * `laravel-authorization` keeps the request's resolved tenant only while the
 * same resolver is bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthorizationSeams implements ProvidesSeams
{
    /** @var string The switch that turns every binding here on or off. */
    public const string SWITCH = 'iam.adapters.authorization';

    /** @var string SSO's switch for linking by a verified domain, which makes the grant hook mandatory. */
    public const string DOMAIN_LINKING = 'sso.features.domain_linking';

    /** @var string The owner `laravel-authorization`'s configuration report names each adapter declared to it by. */
    public const string OWNER = 'laravel-iam';

    /**
     * Constructor.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Holds the application policy the machine mandate asks; `null` reads the configuration alone. */
        private ?Container $container = null,
    ) {}

    /**
     * Return the bindings between `laravel-authorization` and the other
     * members.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on = self::isOn($config);

        $machines = fn (): bool => AccessMandates::acceptsMachineCredentials($config, $this->container);
        $domains  = static fn (): bool => filter_var($config->get(self::DOMAIN_LINKING), FILTER_VALIDATE_BOOL);

        return [
            self::authorizationRow(SubjectResolver::class, SubjectResolverAdapter::class, $on, Lifetime::SCOPED),
            self::authorizationRow(AuthenticationContext::class, AuthenticationContextAdapter::class, $on),
            self::authorizationRow(AuthenticationRequirementChecker::class, RequirementCheckerAdapter::class, $on && MfaSeams::isOn($config)),
            self::authorizationRow(SessionPolicySource::class, SessionPolicySourceAdapter::class, $on, mandatory: $machines),
            new SeamBinding(ScopeRegistry::class, ScopeRegistryAdapter::class, $on, mandatory: $machines),
            new SeamBinding(ApplicationAccess::class, ApplicationAccessAdapter::class, $on, Lifetime::SCOPED, AccessMandates::namesApplicationAccess($config)),
            self::authorizationRow(IdentityDirectory::class, IdentityDirectoryAdapter::class, $on),
            self::authorizationRow(GrantHook::class, GrantHookAdapter::class, self::reportsWidenings($config), mandatory: $domains),
            new SeamBinding(AuditAccessPolicy::class, AuditAccessPolicyAdapter::class, $on, Lifetime::SHARED),
        ];
    }

    /**
     * Whether the switch is on: `false`, `0`, `off` and `no` turn it off, and
     * anything else, a missing value included, leaves it on.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function isOn(Repository $config): bool
    {
        $value = $config->get(self::SWITCH);

        return $value === null || $value === '' || (filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? true);
    }

    /**
     * Whether `laravel-authorization`'s grants are reported to SSO's scope
     * widening, which names each grant's tenant through
     * `laravel-authentication`'s tenant resolver.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function reportsWidenings(Repository $config): bool
    {
        return self::isOn($config) && SsoSeams::isOn($config);
    }

    /**
     * The binding of an adapter over one of `laravel-authorization`'s
     * contracts, declared to its configuration report once bound.
     *
     * @param  class-string  $contract
     * @param  class-string  $adapter
     * @param  bool  $on
     * @param  \SineMacula\Laravel\Iam\Bindings\Enums\Lifetime  $lifetime
     * @param  bool|\Closure(): bool  $mandatory
     * @return \SineMacula\Laravel\Iam\Bindings\SeamBinding
     */
    private static function authorizationRow(string $contract, string $adapter, bool $on, Lifetime $lifetime = Lifetime::TRANSIENT, bool|\Closure $mandatory = false): SeamBinding
    {
        $declare = static function (Container $container, \Closure $bound) use ($contract, $adapter, $lifetime): void {
            Declarations::of($container)->adapter($contract, self::OWNER, $adapter, $lifetime->reported(), $bound);
        };

        return new SeamBinding($contract, $adapter, $on, $lifetime, $mandatory, $declare);
    }
}
