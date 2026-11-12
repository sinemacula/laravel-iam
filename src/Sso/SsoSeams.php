<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy;
use SineMacula\Laravel\Sso\Links\LinkStore;

/**
 * The seams joining `laravel-authentication`, SSO and MFA for SSO, switched by
 * `iam.adapters.sso`.
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

    /**
     * Constructor.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Tells whether the application binds MFA's tenant requirement; with none, only the configuration is read. */
        private ?Container $container = null,
    ) {}

    /**
     * Return the bindings between `laravel-authentication` and SSO.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on       = self::isOn($config);
        $inUse    = self::isInUse($config);
        $enforced = fn (): bool => TenancySeams::isEnforcedOrRequired($config, $this->container);

        return [
            new SeamBinding(ReauthenticationSessions::class, ReauthenticationSessionsAdapter::class, $on, mandatory: $enforced),
            new SeamBinding(SessionRevocation::class, SessionRevocationAdapter::class, $on, mandatory: true),
            new SeamBinding(ExternalIdentityLinks::class, ExternalIdentityLinksAdapter::class, $on, mandatory: $inUse),
            new SeamBinding(Linker::class, LinkStore::class, $on, Lifetime::SCOPED, $inUse),
            new SeamBinding(ExternalEvidencePolicy::class, ExternalEvidencePolicyAdapter::class, $on),
            new SeamBinding(Freshness::class, FreshnessAdapter::class, $on),
            new SeamBinding(ApplicationPolicy::class, ApplicationPolicyAdapter::class, $on),
            new SeamBinding(LinkEmailMatcher::class, LinkEmailMatcherAdapter::class, $on),
            new SeamBinding(LinkConfirmation::class, LinkConfirmationAdapter::class, $on),
            new SeamBinding(EvidencePolicy::class, ConnectionEvidencePolicy::class, $on && self::isEvidenceOn($config), Lifetime::SCOPED),
        ];
    }

    /**
     * Whether the switch is on: only `false`, `0`, `off` or `no` turns it off.
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
     * Whether SSO is in use, as SSO reads the configuration.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function isInUse(Repository $config): bool
    {
        return Features::isInUse($config);
    }

    /**
     * Whether the evidence switch is on, read strictly as it widens trust.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function isEvidenceOn(Repository $config): bool
    {
        return filter_var($config->get(self::EVIDENCE_SWITCH), FILTER_VALIDATE_BOOL);
    }
}
