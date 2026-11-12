<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange as AuthenticationFactorChange;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade as AuthenticationFactorChangeMade;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction as AuthenticationPendingAction;
use SineMacula\Laravel\Mfa\Enums\FactorChange as MfaFactorChange;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade as MfaFactorChangeMade;
use SineMacula\Laravel\Mfa\Enums\PendingAction as MfaPendingAction;

/**
 * Translates factor changes and pending actions between MFA and
 * `laravel-authentication`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ChangeTranslator
{
    /**
     * `laravel-authentication`'s factor change for the one MFA gates.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @return \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange
     */
    public function factorChange(MfaFactorChange $change): AuthenticationFactorChange
    {
        return match ($change) {
            MfaFactorChange::ADD_FIRST_ADDITIONAL_FACTOR => AuthenticationFactorChange::ADD_FIRST,
            MfaFactorChange::ADD_FACTOR                  => AuthenticationFactorChange::ADD,
            MfaFactorChange::REMOVE_FACTOR               => AuthenticationFactorChange::REMOVE,
            MfaFactorChange::GENERATE_RECOVERY_CODES     => AuthenticationFactorChange::GENERATE_RECOVERY_CODES,
        };
    }

    /**
     * `laravel-authentication`'s factor change made for the one MFA made.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChangeMade  $change
     * @return \SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade
     */
    public function factorChangeMade(MfaFactorChangeMade $change): AuthenticationFactorChangeMade
    {
        return match ($change) {
            MfaFactorChangeMade::CONFIRMED          => AuthenticationFactorChangeMade::FACTOR_CONFIRMED,
            MfaFactorChangeMade::PASSKEY_REGISTERED => AuthenticationFactorChangeMade::PASSKEY_FACTOR_REGISTERED,
            MfaFactorChangeMade::REMOVED            => AuthenticationFactorChangeMade::FACTOR_REMOVED,
        };
    }

    /**
     * MFA's pending actions among those allowed, in order, dropping the rest.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction>  $actions
     * @return list<\SineMacula\Laravel\Mfa\Enums\PendingAction>
     */
    public function pendingActions(array $actions): array
    {
        $translated = [];

        foreach ($actions as $action) {

            $pending = MfaPendingAction::tryFrom($action->value);

            if ($pending === null) {
                continue;
            }

            $translated[] = $pending;
        }

        return $translated;
    }

    /**
     * `laravel-authentication`'s pending action for MFA's.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @return \SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction
     */
    public function toAuthenticationAction(MfaPendingAction $action): AuthenticationPendingAction
    {
        return match ($action) {
            MfaPendingAction::LIST_FACTORS                 => AuthenticationPendingAction::LIST_FACTORS,
            MfaPendingAction::SEND_CODE                    => AuthenticationPendingAction::SEND_CODE,
            MfaPendingAction::VERIFY                       => AuthenticationPendingAction::VERIFY,
            MfaPendingAction::START_BOOTSTRAP_ENROLLMENT   => AuthenticationPendingAction::START_BOOTSTRAP_ENROLLMENT,
            MfaPendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT => AuthenticationPendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT,
        };
    }
}
