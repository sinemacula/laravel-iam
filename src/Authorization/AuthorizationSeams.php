<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\Authentication\Applications\AdmitAnyPrincipal;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Scopes\AcceptAnyScope;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Context\GuardAuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\GuardUserIdentityDirectory;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Sso\SsoSeams;

/**
 * The seams `laravel-authorization` joins the other members through
 * (IAM-6.1 to IAM-6.6): its subject resolver, answered from `Auth::caller()`;
 * its authentication context, `laravel-authentication`'s, with the `mfa` and
 * `sso` namespaces; its requirement checker, answered by MFA's requirement
 * check on the session's proofs; its session policy source, answered from the
 * caller's credential scopes; and `laravel-authentication`'s scope registry and
 * application access, answered from `laravel-authorization`. Its
 * insufficient-authentication exception is mapped to MFA's step-up exception
 * beside them (`InsufficientAuthenticationMapping`, registered by the service
 * provider, as a handler's mapping is, rather than bound), and the keys of the
 * authentication context are declared on its key catalogue with their types
 * (`AuthenticationContextKeys`).
 *
 * `laravel-authorization` binds each of its defaults only where nothing is
 * bound yet, and says itself whether a contract still holds its default
 * (`AuthorizationServiceProvider::isPackageDefault()`). So a row over one of
 * its contracts asks it (`authorizationRow()`): the seam is replaced only while
 * it is unbound or holds that default, never where the application binds the
 * contract itself. A class the application names in `laravel-authorization`'s
 * configuration (`authorization.subject_resolver`,
 * `authorization.requirement_checker`, `authorization.session.source`,
 * `authorization.identity_directory`, `authorization.tenant_tree`) is no
 * default, so is kept, and `laravel-authorization`, registering after this
 * package, binds it over the adapter itself, so it stands whichever registers
 * first; this package reads none of those keys.
 *
 * The requirement checker is bound only while the MFA capability's switch is on
 * too, since it is MFA's requirement check that judges, as the mapping of the
 * step-up exception is registered only then. Every adapter here holds nothing
 * between calls and reads what it judges afresh on each, so each is transient,
 * but the subject resolver, application access (IAM-6.6) and the tenant tree,
 * which are scoped, under this package's own `iam.scoped:` keys. The subject
 * resolver is scoped as `laravel-authorization`'s own default is, one for a
 * request or job, since `laravel-authorization` keeps the tenant it resolved
 * for the request only while the resolver bound is the very one that resolved
 * it (`ResolvedTenant::isFrom()`): a resolver built afresh for each check would
 * resolve the subject again on every tenant-scoped read, and each new tenant
 * would empty the request's resolution memo, so every check would read its
 * grants again. It still reads `Auth::caller()` afresh on each call.
 *
 * `laravel-authentication`'s scope registry and `laravel-authorization`'s
 * session policy source are mandatory while any application accepts a machine
 * credential (IAM-6.5), as the bound application policy says, asked only when
 * `iam:check` reads the mandate, never while providers register, and
 * `laravel-authentication`'s application access while
 * `authorization.application_access` maps an application to the permission to
 * use it (`AccessMandates`): left on the members' defaults then, a credential
 * could carry scopes naming no permission, a machine's checks would be capped
 * by nothing, and any principal could use an application whose grants say it
 * may not. `laravel-authorization`'s default source caps no person, and allows
 * nothing only to a machine principal that carries its marker
 * (`AuthorizableMachine`), so it caps a `laravel-authentication` machine
 * without that marker by nothing, which the adapter does not
 * (`SessionPolicySourceAdapter`); `iam:check` refuses that default whatever the
 * switch says (`MandatorySeamsCheck`), the application's own binding of it by
 * its class name included, and passes a source the application names in
 * `laravel-authorization`'s configuration, which `isPackageDefault()` says is
 * no default.
 *
 * The grants and the tree (IAM-6.7, IAM-6.8, IAM-7.5) are bound here too:
 * `laravel-authorization`'s identity directory, answered from
 * `laravel-authentication`'s principals (`IdentityDirectoryAdapter`), so its
 * grant scope query can answer `within` and its grant hook classifies a grant
 * by the identity's real principals; its tenant tree, answered from the
 * application's one tree, and `laravel-authorization`'s own `FlatTenantTree`
 * while the application has none, which the member tells a flat application by
 * (`TenantTreeAdapter::forApplication()`, decided as each request or job first
 * resolves it); and its grant hook, answered by SSO's scope widening
 * (`GrantHookAdapter`), only while the SSO capability's switch is on too, since
 * it is SSO's widening that reports, and mandatory while SSO's linking by a
 * verified domain is on (`sso.features.domain_linking`): left on
 * `laravel-authorization`'s default then, a grant that takes a person beyond a
 * tenant would leave their link by that tenant's verified domain active. Its
 * default is the composite holding no hook (`GrantHooks`), and no configuration
 * key names a class for it: the hooks the application lists in
 * `authorization.grant_hooks` wrap whatever hook is bound, so
 * `laravel-authorization` runs them first and then the adapter, and any of them
 * may refuse the grant. Each holds nothing between calls; the identity
 * directory and the grant hook are transient, and the tree is scoped, under
 * this package's own `iam.scoped:` key, one for a request or job as
 * `laravel-authorization`'s own default is: it keeps the request's tenant
 * chain, and its batch memo of tree reads, only while the tree it reads is the
 * very instance that answered (`ResolvedTenant::chain()`, keyed by the tree
 * instance), so a tree built afresh for each read would walk the application's
 * tree and resolve every ancestor again on every check and every tenant-scoped
 * query. `laravel-authorization` forgets the resolutions read through the
 * subject resolver or the tree when either is bound again, in whichever order
 * the providers register. The grant half of SSO's principal scope is this
 * package's own port, not a member's seam, and is bound by the service provider
 * (`GrantScopeAdapter`).
 *
 * Audit-log's access policy (IAM-6.10) is answered from
 * `laravel-authorization`'s grants too (`AuditAccessPolicyAdapter`), over
 * audit-log's `DenyAllPolicy`, which audit-log binds with `singletonIf()`, so
 * the application's own binding of the policy, before or after, is kept. It is
 * shared, as audit-log's own is, since it reads its grants afresh on every call
 * and keeps nothing. It is not mandatory: left on `DenyAllPolicy`, every read
 * is empty and recorded as denied, which shows nobody anything.
 *
 * Each adapter bound over one of `laravel-authorization`'s contracts is
 * declared to its configuration report (`Diagnostics\Declarations`), owned by
 * `laravel-iam`, with its class, its lifetime and the very closure the binding
 * rule bound over the contract, so `authorization:check` names the adapter
 * while that closure still supplies the contract, and says it was overridden,
 * or that an instance is bound over it, once it does not. The tree, which
 * `TenantTreeAdapter::forApplication()` decides, is declared as a factory of
 * the adapter or `FlatTenantTree`, decided at first resolution. A contract the
 * rule keeps the application's binding on, or a configured class on, is not
 * declared, as nothing of this package's is bound there.
 *
 * The whole capability is switched by `iam.adapters.authorization`: off,
 * nothing here binds or is declared, and each member keeps its own default.
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

    /** @var string SSO's switch for linking by a verified domain, which the grant hook's binding is mandatory while on. */
    public const string DOMAIN_LINKING = 'sso.features.domain_linking';

    /** @var string The owner `laravel-authorization`'s configuration report names each adapter declared to it by. */
    public const string OWNER = 'laravel-iam';

    /** @var string When a factory bound over a contract decides which class it builds, as the report says it. */
    public const string DECIDES = 'at first resolution';

    /**
     * Constructor.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Holds the application policy the scope registry's mandate asks; `null` reads the mandate from the configuration alone. */
        private ?Container $container = null,
    ) {}

    /**
     * Return the bindings between `laravel-authorization` and the other
     * members, each on while the capability's switch is, the requirement
     * checker's only while the MFA capability's is too, and the grant hook's
     * only while the SSO capability's is too.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on  = static fn (Repository $switches): bool => self::isOn($switches);
        $mfa = static fn (Repository $switches): bool => self::isOn($switches) && MfaSeams::isOn($switches);

        $machines = fn (): bool => AccessMandates::acceptsMachineCredentials($config, $this->container);
        $access   = AccessMandates::namesApplicationAccess($config);
        $widening = self::reportsWidenings(...);
        $domains  = static fn (): bool => filter_var($config->get(self::DOMAIN_LINKING), FILTER_VALIDATE_BOOL);

        return [
            self::authorizationRow(SubjectResolver::class, SubjectResolverAdapter::class, AuthGuardSubjectResolver::class, $on, Lifetime::SCOPED),
            self::authorizationRow(AuthenticationContext::class, AuthenticationContextAdapter::class, GuardAuthenticationContext::class, $on),
            self::authorizationRow(AuthenticationRequirementChecker::class, RequirementCheckerAdapter::class, RefusingRequirementChecker::class, $mfa),
            self::authorizationRow(SessionPolicySource::class, SessionPolicySourceAdapter::class, NoSessionPolicy::class, $on, mandatory: $machines),
            new SeamBinding(ScopeRegistry::class, ScopeRegistryAdapter::class, [AcceptAnyScope::class], appliesWhen: $on, mandatory: $machines),
            new SeamBinding(ApplicationAccess::class, ApplicationAccessAdapter::class, [AdmitAnyPrincipal::class], Lifetime::SCOPED, appliesWhen: $on, mandatory: $access),
            self::authorizationRow(IdentityDirectory::class, IdentityDirectoryAdapter::class, GuardUserIdentityDirectory::class, $on),
            self::authorizationRow(TenantTree::class, TenantTreeAdapter::class, FlatTenantTree::class, $on, Lifetime::SCOPED, factory: TenantTreeAdapter::forApplication(...)),
            self::authorizationRow(GrantHook::class, GrantHookAdapter::class, GrantHooks::class, $widening, mandatory: $domains),
            new SeamBinding(AuditAccessPolicy::class, AuditAccessPolicyAdapter::class, [DenyAllPolicy::class], Lifetime::SHARED, appliesWhen: $on),
        ];
    }

    /**
     * Whether the capability's switch leaves its bindings on, read leniently,
     * as the members read a switch an environment variable fills: `false`, as a
     * boolean or as text, `0`, `off` and `no` turn it off; anything else, a
     * missing or empty value included, leaves it on, since the package requires
     * every member and binds them together unless told not to.
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
     * widening: while both capabilities' switches are on, the grant hook's row
     * applies, so every grant that widens an identity's scope in a tenant names
     * that tenant through `laravel-authentication`'s tenant resolver.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function reportsWidenings(Repository $config): bool
    {
        return self::isOn($config) && SsoSeams::isOn($config);
    }

    /**
     * The binding of the adapter over one of `laravel-authorization`'s
     * contracts: replaced only while the contract is unbound or holds
     * `laravel-authorization`'s own default, as
     * `AuthorizationServiceProvider::isPackageDefault()` says, with the
     * lifetime and the mandate given, built by the factory given, if any, and
     * declared to `laravel-authorization`'s configuration report once bound.
     * The default class is named so the checks name the default they refuse,
     * and refuse it bound by its class name.
     *
     * @param  class-string  $contract
     * @param  class-string  $adapter
     * @param  class-string  $default
     * @param  \Closure(\Illuminate\Contracts\Config\Repository): bool  $appliesWhen
     * @param  \SineMacula\Laravel\Iam\Bindings\Enums\Lifetime  $lifetime
     * @param  bool|\Closure(): bool  $mandatory
     * @param  ?\Closure(\Illuminate\Contracts\Container\Container): object  $factory
     * @return \SineMacula\Laravel\Iam\Bindings\SeamBinding
     */
    private static function authorizationRow(
        string $contract,
        string $adapter,
        string $default,
        \Closure $appliesWhen,
        Lifetime $lifetime = Lifetime::TRANSIENT,
        bool|\Closure $mandatory = false,
        ?\Closure $factory = null,
    ): SeamBinding {
        return new SeamBinding(
            $contract,
            $adapter,
            [$default],
            $lifetime,
            appliesWhen: $appliesWhen,
            mandatory: $mandatory,
            holdsDefault: AuthorizationServiceProvider::isPackageDefault(...),
            factory: $factory,
            declare: self::declaration($contract, $adapter, $default, $lifetime, $factory !== null),
        );
    }

    /**
     * How the adapter bound over one of `laravel-authorization`'s contracts is
     * declared to its configuration report, handed the container and the
     * closure the binding rule bound over the contract: as the adapter, or, for
     * a row built by a factory, as a factory of the adapter or the member's
     * default, decided at first resolution; with the row's lifetime.
     *
     * @param  class-string  $contract
     * @param  class-string  $adapter
     * @param  class-string  $default
     * @param  \SineMacula\Laravel\Iam\Bindings\Enums\Lifetime  $lifetime
     * @param  bool  $isFactory
     * @return \Closure(\Illuminate\Contracts\Container\Container, (\Closure(mixed...): mixed)|null): void
     */
    private static function declaration(string $contract, string $adapter, string $default, Lifetime $lifetime, bool $isFactory): \Closure
    {
        if ($isFactory) {
            return static function (Container $container, ?\Closure $bound) use ($contract, $adapter, $default, $lifetime): void {
                Declarations::of($container)->factory($contract, self::OWNER, [$adapter, $default], self::DECIDES, $lifetime->reported(), $bound);
            };
        }

        return static function (Container $container, ?\Closure $bound) use ($contract, $adapter, $lifetime): void {
            Declarations::of($container)->adapter($contract, self::OWNER, $adapter, $lifetime->reported(), $bound);
        };
    }
}
