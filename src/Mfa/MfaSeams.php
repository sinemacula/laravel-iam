<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck as AuthenticationRequirementCheck;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Testing\VerifiedSignInRecorderAdapter;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder;

/**
 * The seams `laravel-authentication` and MFA join through (IAM-3.1 to
 * IAM-3.13), switched by `iam.adapters.mfa`. Every adapter is transient and
 * reads the request afresh on each call (IAM-8.1). The recorder MFA's
 * `actingAsVerified()` signs in through, which MFA leaves unbound, is bound
 * here too. Revocation on factor removal and reset is mandatory (IAM-3.7).
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
     * Return the bindings between `laravel-authentication` and MFA.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on = self::isOn($config);

        return [
            new SeamBinding(AdditionalFactorPolicy::class, AdditionalFactorPolicyAdapter::class, $on),
            new SeamBinding(AuthenticationRequirementCheck::class, RequirementCheckAdapter::class, $on),
            new SeamBinding(PendingSessionResolver::class, PendingSessionResolverAdapter::class, $on),
            new SeamBinding(PendingCompletion::class, PendingCompletionAdapter::class, $on),
            new SeamBinding(StepUp::class, StepUpAdapter::class, $on),
            new SeamBinding(Reauthenticator::class, ReauthenticatorAdapter::class, $on),
            new SeamBinding(FreshnessGate::class, FreshnessGateAdapter::class, $on),
            new SeamBinding(FactorChangeGate::class, FactorChangeGateAdapter::class, $on),
            new SeamBinding(SessionRevoker::class, SessionRevokerAdapter::class, $on, mandatory: true),
            new SeamBinding(SessionTransition::class, SessionTransitionAdapter::class, $on),
            new SeamBinding(ProofStore::class, ProofStoreAdapter::class, $on),
            new SeamBinding(FirstFactorResolver::class, FirstFactorResolverAdapter::class, $on),
            new SeamBinding(VerifiedSignInRecorder::class, VerifiedSignInRecorderAdapter::class, $on),
            new SeamBinding(ChallengeGateway::class, ChallengeGatewayAdapter::class, $on),
            new SeamBinding(SmsSender::class, CodeSenderAdapter::class, $on),
            new SeamBinding(EmailSender::class, CodeSenderAdapter::class, $on),
            new SeamBinding(FactorCodeCounters::class, FactorCodeCountersAdapter::class, $on),
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
}
