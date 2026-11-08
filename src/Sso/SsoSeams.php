<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\External\InsufficientEvidence as InsufficientExternalEvidence;
use SineMacula\Laravel\Authentication\External\NoExternalLinks;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Sso\Applications\ConfiguredApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy;
use SineMacula\Laravel\Sso\Evidence\InsufficientEvidence;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Linking\NoEmailMatches;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;

/**
 * The seams `laravel-authentication`, SSO and MFA join through for SSO (IAM-4.2
 * to IAM-4.4, IAM-4.6, IAM-4.7, IAM-4.9, IAM-5.1): re-authentication sessions,
 * session revocation, the external identity links, SSO's own link store, the
 * provider's evidence, freshness, the application's external sign-in and the
 * link email matcher.
 *
 * - SSO's `ReauthenticationSessions` is answered from
 *   `laravel-authentication`'s external standing, with its renewal recorded for
 *   the redemption's one write (`ReauthenticationSessionsAdapter`). It is
 *   mandatory while SSO's enforcement is on or the application names or binds a
 *   tenant MFA requirement (IAM-10.2): left on SSO's default then, nobody held
 *   to a tenant's rule could renew a session through the connection the rule
 *   names.
 * - SSO's `SessionRevocation` ends `laravel-authentication`'s sessions inside
 *   SSO's change (`SessionRevocationAdapter`). It is mandatory: left on SSO's
 *   default, an enforcement change, a disabled or deleted connection, a removed
 *   link or a widened scope would leave every session it concerns standing.
 * - `laravel-authentication`'s `ExternalIdentityLinks` answers from the
 *   redemption SSO admitted in this request alone
 *   (`ExternalIdentityLinksAdapter`). It is mandatory while SSO is in use, a
 *   protocol switched on (IAM-10.2): left on the default, no sign-in through
 *   SSO would find its identity.
 * - SSO's `Linker` is SSO's own `Links\LinkStore`, which implements
 *   `LinkStorage` too: links are SSO's, and `laravel-authentication` stores
 *   none. SSO finds its link storage only as the linker bound, so `LinkStorage`
 *   is answered from whatever linker is bound (`BoundLinkStorage`), the store
 *   by default, and never from a store of its own that an application's own
 *   linker would not see. SSO binds no link storage of its own, so that seam is
 *   bound only while unbound. Neither keeps anything of one request for the
 *   next, but each holds the container (the store resolves its link limit and
 *   its reporter from it), so both are scoped, as SSO's own guide binds the
 *   store, and a long-lived worker never reaches one request's container from
 *   another (IAM-8.1). Both are mandatory while SSO is in use (IAM-10.2): left
 *   on SSO's `NoLinks`, or unbound, no link could be made or found. SSO's own
 *   `LinkStore` is accepted on the link storage as well
 *   (`SeamBinding::$accepted`), since SSO's guide binds both seams to it: it is
 *   SSO's real store, not a permissive default.
 *
 * - `laravel-authentication`'s `ExternalEvidencePolicy` is answered from the
 *   evidence SSO accepted, with MFA's `CombinationPolicy` as the second gate
 *   (`ExternalEvidencePolicyAdapter`), so a provider's `amr` is not multifactor
 *   authentication unless MFA's policy is rebound to trust the connection.
 * - SSO's `EvidencePolicy`, the first gate, is bound to SSO's own
 *   `Evidence\ConnectionEvidencePolicy` only while `iam.sso.evidence` is on as
 *   well, read strictly, since accepting a provider's evidence widens what a
 *   session can satisfy: only `true`, `1`, `on` and `yes` turn it on. Off, SSO
 *   keeps its default, which accepts nothing. It keeps nothing of one call for
 *   the next but holds the settings it reads, so it is scoped, as SSO's own
 *   documentation binds it.
 * - SSO's `Freshness` asks `laravel-authentication`'s freshness policy with
 *   SSO's maximum age as the caller's requirement (`FreshnessAdapter`).
 * - SSO's `ApplicationPolicy` is answered by `laravel-authentication`'s sign-in
 *   methods for the guard of the same name (`ApplicationPolicyAdapter`).
 * - SSO's `LinkEmailMatcher` matches the identities' verified email addresses
 *   through `laravel-authentication`'s normaliser (`LinkEmailMatcherAdapter`).
 *
 * The `sso` namespace of `laravel-authentication`'s authentication context is
 * no seam: its contributor (`SsoContextContributor`) is registered in the
 * service provider's `boot()`, under the same switch. The tenant authentication
 * policy SSO's enforcement folds into is declared apart
 * (`Tenancy\TenancySeams`), since the tenant MFA requirement is its source too.
 *
 * SSO's handoff issuer is never bound: SSO issues and redeems its own handoff
 * codes, so it keeps its default, `Handoffs\DatabaseHandoffStore`.
 *
 * Each adapter replaces the member's own default only; an application's binding
 * is kept (IAM-8.4). The adapters keep nothing and resolve the records this
 * package keeps for a redemption (`AdmittedRedemptions`, `RenewalRecorder`,
 * `LinkCallers`) on every call, so each is transient. The whole capability is
 * switched by `iam.adapters.sso`: off, nothing here binds, and each member
 * keeps its own default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoSeams implements ProvidesSeams
{
    /** @var string The switch that turns every binding here on or off. */
    public const string SWITCH = 'iam.adapters.sso';

    /** @var string The switch that binds SSO's per-connection evidence policy, while the capability's is on. */
    public const string EVIDENCE_SWITCH = 'iam.sso.evidence';

    /** @var list<string> SSO's protocol switches, any of which puts SSO in use. */
    public const array PROTOCOLS = ['sso.features.saml2', 'sso.features.oidc'];

    /** @var list<mixed> The values SSO reads a switch as off from; any other value is on, or malformed, and so may have been meant to be. */
    private const array OFF = [false, 0, '0', 'false'];

    /**
     * Constructor.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Tells whether the application has bound a tenant MFA requirement, which the re-authentication sessions' mandate reads; with none, only the configuration is read. */
        private ?Container $container = null,
    ) {}

    /**
     * Return the bindings between `laravel-authentication` and SSO, each on
     * while the capability's switch is; session revocation always mandatory,
     * the links and the link stores while SSO is in use, and the
     * re-authentication sessions while SSO's enforcement or a tenant MFA
     * requirement is on.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on       = static fn (Repository $switches): bool => self::isOn($switches);
        $evidence = static fn (Repository $switches): bool => self::isOn($switches) && self::isEvidenceOn($switches);
        $inUse    = self::isInUse($config);
        $enforced = TenancySeams::isEnforcedOrRequired($config, $this->container);

        return [
            new SeamBinding(ReauthenticationSessions::class, ReauthenticationSessionsAdapter::class, [NoReauthenticationSessions::class], appliesWhen: $on, mandatory: $enforced),
            new SeamBinding(SessionRevocation::class, SessionRevocationAdapter::class, [NoSessionRevocation::class], appliesWhen: $on, mandatory: true),
            new SeamBinding(ExternalIdentityLinks::class, ExternalIdentityLinksAdapter::class, [NoExternalLinks::class], appliesWhen: $on, mandatory: $inUse),
            new SeamBinding(Linker::class, LinkStore::class, [NoLinks::class], Lifetime::SCOPED, $on, $inUse),
            new SeamBinding(LinkStorage::class, BoundLinkStorage::class, [], Lifetime::SCOPED, $on, $inUse, [LinkStore::class]),
            new SeamBinding(ExternalEvidencePolicy::class, ExternalEvidencePolicyAdapter::class, [InsufficientExternalEvidence::class], appliesWhen: $on),
            new SeamBinding(Freshness::class, FreshnessAdapter::class, [RefusingFreshness::class], appliesWhen: $on),
            new SeamBinding(ApplicationPolicy::class, ApplicationPolicyAdapter::class, [ConfiguredApplicationPolicy::class], appliesWhen: $on),
            new SeamBinding(LinkEmailMatcher::class, LinkEmailMatcherAdapter::class, [NoEmailMatches::class], appliesWhen: $on),
            new SeamBinding(EvidencePolicy::class, ConnectionEvidencePolicy::class, [InsufficientEvidence::class], Lifetime::SCOPED, $evidence),
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
     * Whether SSO is in use, read as SSO's own `Config\Features::isInUse()`
     * reads it, from the configuration given: a protocol is switched on, or its
     * switch is malformed, and so may have been meant to be.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function isInUse(Repository $config): bool
    {
        foreach (self::PROTOCOLS as $key) {

            if (!in_array($config->get($key, false), self::OFF, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the evidence switch binds SSO's per-connection evidence policy,
     * read strictly, since it widens what a provider's assertion can count
     * for: `true`, as a boolean or as text, `1`, `on` and `yes` turn it on;
     * anything else, a missing, empty or unrecognised value included, leaves it
     * off.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function isEvidenceOn(Repository $config): bool
    {
        return filter_var($config->get(self::EVIDENCE_SWITCH), FILTER_VALIDATE_BOOL);
    }
}
