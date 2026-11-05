<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\Authentication\Applications\AdmitAnyPrincipal;
use SineMacula\Laravel\Authentication\Codes\RefuseFactorCodes;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\IdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver as AuthenticationPrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver as AuthenticationTenantResolver;
use SineMacula\Laravel\Authentication\External\InsufficientEvidence as AuthenticationInsufficientEvidence;
use SineMacula\Laravel\Authentication\External\NoExternalLinks;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Passkeys\NoPasskeyFactors;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use SineMacula\Laravel\Authentication\Tenancy\OwnTenantOnly;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver as AuthorizationPrincipalResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantResolver as AuthorizationTenantResolver;
use SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactorResolver;
use SineMacula\Laravel\Mfa\Codes\NullEmailSender;
use SineMacula\Laravel\Mfa\Codes\NullSmsSender;
use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Context\NoPendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Contracts\SelfServiceRecovery;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Lifecycle\NoSelfServiceRecovery;
use SineMacula\Laravel\Mfa\Passkeys\UnavailablePasskeyGateway;
use SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\ProofBindings;
use SineMacula\Laravel\Mfa\Requirements\NoActiveTenant;
use SineMacula\Laravel\Mfa\Requirements\NoTenantRequirement;
use SineMacula\Laravel\Mfa\Seams\RefusingReauthenticator;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Evidence\InsufficientEvidence as SsoInsufficientEvidence;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Linking\NoEmailMatches;
use SineMacula\Laravel\Sso\Linking\NoTenantMembership;
use SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation;
use SineMacula\Laravel\Sso\Linking\RefusingLinkEligibility;
use SineMacula\Laravel\Sso\Linking\RefusingPrincipalScope;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;

/**
 * A seam table the size of the one the package binds once every capability has
 * its adapters, over real member seams and the defaults the members bind them
 * to: class-string defaults, plain `singleton()`, `bindIf()` and
 * `singletonIf()` alike, two defaults the members bind with a closure, and two
 * seams no member binds.
 *
 * Every row binds the same adapter, `BenchSeamAdapter`, and is switched by the
 * `iam.adapters` key of the member pair it joins, on unless the configuration
 * turns it off. The binding rule binds without resolving, so no adapter has to
 * implement its seam.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BenchSeamTable
{
    /** @var list<array{class-string, list<class-string>, \SineMacula\Laravel\Iam\Bindings\Enums\Lifetime, string}> Seam, member defaults, lifetime and switch. */
    private const array ROWS = [
        [AdditionalFactorPolicy::class, [NeverRequireAdditionalFactor::class], Lifetime::TRANSIENT, 'mfa'],
        [PasskeyFactorGate::class, [NoPasskeyFactors::class], Lifetime::TRANSIENT, 'mfa'],
        [RequirementCheck::class, [MeetNoRequirement::class], Lifetime::TRANSIENT, 'mfa'],
        [FactorCodeCounters::class, [RefuseFactorCodes::class], Lifetime::TRANSIENT, 'mfa'],
        [FreshnessPolicy::class, [ConfiguredFreshness::class], Lifetime::TRANSIENT, 'mfa'],
        [TenantAuthenticationPolicy::class, [RequireNothingOfTenants::class], Lifetime::TRANSIENT, 'mfa'],
        [OneTimeCodeSender::class, [], Lifetime::TRANSIENT, 'mfa'],
        [IdentifierChangeNotifier::class, [], Lifetime::TRANSIENT, 'mfa'],
        [ExternalIdentityLinks::class, [NoExternalLinks::class], Lifetime::TRANSIENT, 'sso'],
        [ExternalEvidencePolicy::class, [AuthenticationInsufficientEvidence::class], Lifetime::TRANSIENT, 'sso'],
        [ApplicationAccess::class, [AdmitAnyPrincipal::class], Lifetime::SCOPED, 'authorization'],
        [TenantAccess::class, [OwnTenantOnly::class], Lifetime::TRANSIENT, 'authorization'],
        [AuthenticationTenantResolver::class, [ResolveNoTenant::class], Lifetime::SCOPED, 'authorization'],
        [AuthenticationPrincipalResolver::class, [DefaultPrincipalResolver::class], Lifetime::TRANSIENT, 'authorization'],
        [PendingSessionResolver::class, [NoPendingSessionResolver::class], Lifetime::SCOPED, 'mfa'],
        [EventContextResolver::class, [DefaultEventContextResolver::class], Lifetime::TRANSIENT, 'mfa'],
        [Reauthenticator::class, [RefusingReauthenticator::class], Lifetime::TRANSIENT, 'mfa'],
        [SmsSender::class, [NullSmsSender::class], Lifetime::TRANSIENT, 'mfa'],
        [EmailSender::class, [NullEmailSender::class], Lifetime::TRANSIENT, 'mfa'],
        [TenantRequirement::class, [NoTenantRequirement::class], Lifetime::TRANSIENT, 'mfa'],
        [ActiveTenantResolver::class, [NoActiveTenant::class], Lifetime::SCOPED, 'mfa'],
        [FirstFactorResolver::class, [DeclaredFirstFactorResolver::class], Lifetime::TRANSIENT, 'mfa'],
        [ProofStore::class, [ProofBindings::class], Lifetime::TRANSIENT, 'mfa'],
        [SessionRevoker::class, [GenerationSessionRevoker::class], Lifetime::TRANSIENT, 'mfa'],
        [SelfServiceRecovery::class, [NoSelfServiceRecovery::class], Lifetime::TRANSIENT, 'mfa'],
        [PasskeyGateway::class, [UnavailablePasskeyGateway::class], Lifetime::TRANSIENT, 'mfa'],
        [SessionRevocation::class, [NoSessionRevocation::class], Lifetime::TRANSIENT, 'sso'],
        [Linker::class, [NoLinks::class], Lifetime::TRANSIENT, 'sso'],
        [ReauthenticationSessions::class, [NoReauthenticationSessions::class], Lifetime::SCOPED, 'sso'],
        [LinkEligibility::class, [RefusingLinkEligibility::class], Lifetime::TRANSIENT, 'sso'],
        [LinkConfirmation::class, [RefusingLinkConfirmation::class], Lifetime::TRANSIENT, 'sso'],
        [LinkEmailMatcher::class, [NoEmailMatches::class], Lifetime::TRANSIENT, 'sso'],
        [PrincipalScope::class, [RefusingPrincipalScope::class], Lifetime::TRANSIENT, 'sso'],
        [TenantMembership::class, [NoTenantMembership::class], Lifetime::TRANSIENT, 'sso'],
        [EvidencePolicy::class, [SsoInsufficientEvidence::class], Lifetime::TRANSIENT, 'sso'],
        [Freshness::class, [RefusingFreshness::class], Lifetime::TRANSIENT, 'sso'],
        [AuthorizationPrincipalResolver::class, [NullPrincipalResolver::class], Lifetime::TRANSIENT, 'authorization'],
        [AuthorizationTenantResolver::class, [NullTenantResolver::class], Lifetime::SCOPED, 'authorization'],
        [AuditAccessPolicy::class, [DenyAllPolicy::class], Lifetime::SHARED, 'audit'],
        [CheckpointAnchor::class, [AuditLogServiceProvider::class], Lifetime::TRANSIENT, 'audit'],
    ];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Return the table's bindings, in its order.
     *
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    public static function bindings(): array
    {
        return array_map(static fn (array $row): SeamBinding => new SeamBinding(
            $row[0],
            BenchSeamAdapter::class,
            $row[1],
            $row[2],
            static fn (Repository $config): bool => $config->get('iam.adapters.' . $row[3], true) !== false,
        ), self::ROWS);
    }

    /**
     * Return the seams the table binds, in its order.
     *
     * @return list<class-string>
     */
    public static function seams(): array
    {
        return array_column(self::ROWS, 0);
    }

    /**
     * Return the switches the table's rows read, each once.
     *
     * @return list<string>
     */
    public static function switches(): array
    {
        return array_values(array_unique(array_column(self::ROWS, 3)));
    }
}
