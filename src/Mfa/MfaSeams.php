<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Codes\RefuseFactorCodes;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck as AuthenticationRequirementCheck;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Delivery\DeliverySeams;
use SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactorResolver;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Context\NoPendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Http\MiddlewareSessionTransition;
use SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\ProofBindings;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFactorChangeGate;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Seams\RefusingReauthenticator;

/**
 * The seams `laravel-authentication` and MFA join through (IAM-3.1 to IAM-3.9,
 * IAM-3.11): requirements, pending sessions and their completion, step-up,
 * reauthentication and freshness, factor changes, revocation, the return to
 * pending, code challenges and their counters, the proof store and the first
 * factor. Passkeys as factors (IAM-3.10) and MFA's context (IAM-3.12) are
 * declared beside them, in `PasskeySeams` and `ContextSeams`, under the same
 * switch.
 *
 * Each adapter replaces the member's own default only; an application's binding
 * is kept (IAM-8.4). MFA's proof store default is bound with a closure its
 * proof bindings declare, so that class names it. Every adapter is transient:
 * none keeps state, and each reads the request's (the guard's current session)
 * afresh on every call, so nothing reaches another request or job (IAM-8.1).
 * Revocation on factor removal and reset is mandatory (IAM-3.7): left on MFA's
 * default, a removed factor would leave every other session of the identity
 * standing.
 *
 * MFA's challenge gateway is pointed at `laravel-authentication`'s factor codes
 * while that path can deliver them (`DeliverySeams::routesFactorCodes()`:
 * `laravel-authentication`'s one-time code sender is bound); otherwise MFA
 * keeps its own challenges. The adapter then sends on that path only the codes
 * it delivers as MFA would, judged code by code against the container as it
 * stands, and hands every other to MFA's own challenge gateway, so a sender or
 * a driver the application binds or registers, before this package registers or
 * after, is the one its codes go through, and MFA's boot check judges the
 * senders they really go through.
 *
 * The whole capability is switched by `iam.adapters.mfa`: off, nothing here
 * binds, and each member keeps its own default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MfaSeams implements ProvidesSeams
{
    /** @var string The switch that turns every binding here on or off. */
    public const string SWITCH = 'iam.adapters.mfa';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\DeliverySeams  $delivery
     */
    public function __construct(

        /** Tells whether `laravel-authentication`'s path can deliver MFA's factor codes. */
        private DeliverySeams $delivery,
    ) {}

    /**
     * Return the bindings between `laravel-authentication` and MFA, each on
     * while the capability's switch is, and the challenge gateway's only while
     * `laravel-authentication`'s path can deliver MFA's codes too.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on     = static fn (Repository $switches): bool => self::isOn($switches);
        $routed = fn (Repository $switches): bool => self::isOn($switches) && $this->delivery->routesFactorCodes($switches);

        return [
            new SeamBinding(AdditionalFactorPolicy::class, AdditionalFactorPolicyAdapter::class, [NeverRequireAdditionalFactor::class], appliesWhen: $on),
            new SeamBinding(AuthenticationRequirementCheck::class, RequirementCheckAdapter::class, [MeetNoRequirement::class], appliesWhen: $on),
            new SeamBinding(PendingSessionResolver::class, PendingSessionResolverAdapter::class, [NoPendingSessionResolver::class], appliesWhen: $on),
            new SeamBinding(PendingCompletion::class, PendingCompletionAdapter::class, [ProofStoreCompletion::class], appliesWhen: $on),
            new SeamBinding(StepUp::class, StepUpAdapter::class, [ProofStoreCompletion::class], appliesWhen: $on),
            new SeamBinding(Reauthenticator::class, ReauthenticatorAdapter::class, [RefusingReauthenticator::class], appliesWhen: $on),
            new SeamBinding(FreshnessGate::class, FreshnessGateAdapter::class, [ConfiguredFreshnessGate::class], appliesWhen: $on),
            new SeamBinding(FactorChangeGate::class, FactorChangeGateAdapter::class, [ConfiguredFactorChangeGate::class], appliesWhen: $on),
            new SeamBinding(SessionRevoker::class, SessionRevokerAdapter::class, [GenerationSessionRevoker::class], appliesWhen: $on, mandatory: true),
            new SeamBinding(SessionTransition::class, SessionTransitionAdapter::class, [MiddlewareSessionTransition::class], appliesWhen: $on),
            new SeamBinding(ProofStore::class, ProofStoreAdapter::class, [ProofBindings::class], appliesWhen: $on),
            new SeamBinding(FirstFactorResolver::class, FirstFactorResolverAdapter::class, [DeclaredFirstFactorResolver::class], appliesWhen: $on),
            new SeamBinding(ChallengeGateway::class, ChallengeGatewayAdapter::class, [PackageChallengeGateway::class], appliesWhen: $routed),
            new SeamBinding(FactorCodeCounters::class, FactorCodeCountersAdapter::class, [RefuseFactorCodes::class], appliesWhen: $on),
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
}
