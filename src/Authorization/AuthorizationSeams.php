<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Applications\AdmitAnyPrincipal;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Scopes\AcceptAnyScope;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Context\GuardAuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;

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
 * `authorization.requirement_checker`, `authorization.session.source`) is no
 * default, so is kept, and `laravel-authorization`, registering after this
 * package, binds it over the adapter itself, so it stands whichever registers
 * first; this package reads none of those keys.
 *
 * The requirement checker is bound only while the MFA capability's switch is on
 * too, since it is MFA's requirement check that judges, as the mapping of the
 * step-up exception is registered only then. Every adapter here holds nothing
 * between calls and reads what it judges afresh on each, so each is transient,
 * but the subject resolver and application access (IAM-6.6), which are scoped,
 * under this package's own `iam.scoped:` keys. The subject resolver is scoped
 * as `laravel-authorization`'s own default is, one for a request or job, since
 * `laravel-authorization` keeps the tenant it resolved for the request only
 * while the resolver bound is the very one that resolved it
 * (`ResolvedTenant::isFrom()`): a resolver built afresh for each check would
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
 * The whole capability is switched by `iam.adapters.authorization`: off,
 * nothing here binds, and each member keeps its own default.
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
     * members, each on while the capability's switch is, and the requirement
     * checker's only while the MFA capability's is too.
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

        return [
            self::authorizationRow(SubjectResolver::class, SubjectResolverAdapter::class, AuthGuardSubjectResolver::class, $on, Lifetime::SCOPED),
            self::authorizationRow(AuthenticationContext::class, AuthenticationContextAdapter::class, GuardAuthenticationContext::class, $on),
            self::authorizationRow(AuthenticationRequirementChecker::class, RequirementCheckerAdapter::class, RefusingRequirementChecker::class, $mfa),
            self::authorizationRow(SessionPolicySource::class, SessionPolicySourceAdapter::class, NoSessionPolicy::class, $on, mandatory: $machines),
            new SeamBinding(ScopeRegistry::class, ScopeRegistryAdapter::class, [AcceptAnyScope::class], appliesWhen: $on, mandatory: $machines),
            new SeamBinding(ApplicationAccess::class, ApplicationAccessAdapter::class, [AdmitAnyPrincipal::class], Lifetime::SCOPED, appliesWhen: $on, mandatory: $access),
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
     * The binding of the adapter over one of `laravel-authorization`'s
     * contracts: replaced only while the contract is unbound or holds
     * `laravel-authorization`'s own default, as
     * `AuthorizationServiceProvider::isPackageDefault()` says, with the
     * lifetime and the mandate given. The default class is named so the checks
     * name the default they refuse, and refuse it bound by its class name.
     *
     * @param  class-string  $contract
     * @param  class-string  $adapter
     * @param  class-string  $default
     * @param  \Closure(\Illuminate\Contracts\Config\Repository): bool  $appliesWhen
     * @param  \SineMacula\Laravel\Iam\Bindings\Enums\Lifetime  $lifetime
     * @param  bool|\Closure(): bool  $mandatory
     * @return \SineMacula\Laravel\Iam\Bindings\SeamBinding
     */
    private static function authorizationRow(
        string $contract,
        string $adapter,
        string $default,
        \Closure $appliesWhen,
        Lifetime $lifetime = Lifetime::TRANSIENT,
        bool|\Closure $mandatory = false,
    ): SeamBinding {
        return new SeamBinding(
            $contract,
            $adapter,
            [$default],
            $lifetime,
            appliesWhen: $appliesWhen,
            mandatory: $mandatory,
            holdsDefault: AuthorizationServiceProvider::isPackageDefault(...),
        );
    }
}
