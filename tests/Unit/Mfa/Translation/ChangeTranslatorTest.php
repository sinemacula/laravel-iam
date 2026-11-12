<?php

declare(strict_types = 1);

namespace Tests\Unit\Mfa\Translation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange as AuthenticationFactorChange;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade as AuthenticationFactorChangeMade;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction as AuthenticationPendingAction;
use SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator;
use SineMacula\Laravel\Mfa\Enums\FactorChange as MfaFactorChange;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade as MfaFactorChangeMade;
use SineMacula\Laravel\Mfa\Enums\PendingAction as MfaPendingAction;

/**
 * Unit tests for translating factor changes and pending actions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChangeTranslator::class)]
final class ChangeTranslatorTest extends TestCase
{
    /**
     * Rows of `[MFA's factor change, laravel-authentication's]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\FactorChange, 1: \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange}>
     */
    public static function provideFactorChanges(): iterable
    {
        yield 'add the first additional factor' => [MfaFactorChange::ADD_FIRST_ADDITIONAL_FACTOR, AuthenticationFactorChange::ADD_FIRST];

        yield 'add a factor' => [MfaFactorChange::ADD_FACTOR, AuthenticationFactorChange::ADD];

        yield 'remove a factor' => [MfaFactorChange::REMOVE_FACTOR, AuthenticationFactorChange::REMOVE];

        yield 'generate recovery codes' => [MfaFactorChange::GENERATE_RECOVERY_CODES, AuthenticationFactorChange::GENERATE_RECOVERY_CODES];
    }

    /**
     * Every factor change MFA gates crosses as the one of the same value.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $mfa
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChange  $authentication
     * @return void
     */
    #[DataProvider('provideFactorChanges')]
    public function testEveryFactorChangeIsLaravelAuthenticationsOfTheSameValue(MfaFactorChange $mfa, AuthenticationFactorChange $authentication): void
    {
        self::assertSame($authentication, (new ChangeTranslator)->factorChange($mfa));
        self::assertSame($mfa->value, $authentication->value);
    }

    /**
     * Rows of `[MFA's factor change made, laravel-authentication's]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\FactorChangeMade, 1: \SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade}>
     */
    public static function provideFactorChangesMade(): iterable
    {
        yield 'confirmed' => [MfaFactorChangeMade::CONFIRMED, AuthenticationFactorChangeMade::FACTOR_CONFIRMED];

        yield 'passkey registered' => [MfaFactorChangeMade::PASSKEY_REGISTERED, AuthenticationFactorChangeMade::PASSKEY_FACTOR_REGISTERED];

        yield 'removed' => [MfaFactorChangeMade::REMOVED, AuthenticationFactorChangeMade::FACTOR_REMOVED];
    }

    /**
     * Every factor change MFA makes crosses as the one of the same value.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChangeMade  $mfa
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade  $authentication
     * @return void
     */
    #[DataProvider('provideFactorChangesMade')]
    public function testEveryFactorChangeMadeIsLaravelAuthenticationsOfTheSameValue(MfaFactorChangeMade $mfa, AuthenticationFactorChangeMade $authentication): void
    {
        self::assertSame($authentication, (new ChangeTranslator)->factorChangeMade($mfa));
        self::assertSame($mfa->value, $authentication->value);
    }

    /**
     * Rows of `[MFA's pending action, laravel-authentication's]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\PendingAction, 1: \SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction}>
     */
    public static function providePendingActions(): iterable
    {
        yield 'list factors' => [MfaPendingAction::LIST_FACTORS, AuthenticationPendingAction::LIST_FACTORS];

        yield 'send a code' => [MfaPendingAction::SEND_CODE, AuthenticationPendingAction::SEND_CODE];

        yield 'verify' => [MfaPendingAction::VERIFY, AuthenticationPendingAction::VERIFY];

        yield 'start a bootstrap enrolment' => [MfaPendingAction::START_BOOTSTRAP_ENROLLMENT, AuthenticationPendingAction::START_BOOTSTRAP_ENROLLMENT];

        yield 'confirm a bootstrap enrolment' => [MfaPendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT, AuthenticationPendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT];
    }

    /**
     * Every pending action MFA takes crosses as itself, both ways.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $mfa
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction  $authentication
     * @return void
     */
    #[DataProvider('providePendingActions')]
    public function testEveryPendingActionCrossesAsItself(MfaPendingAction $mfa, AuthenticationPendingAction $authentication): void
    {
        $translator = new ChangeTranslator;

        self::assertSame([$mfa], $translator->pendingActions([$authentication]));
        self::assertSame($authentication, $translator->toAuthenticationAction($mfa));
    }

    /**
     * The pending actions MFA does not take are left out, in order.
     *
     * @return void
     */
    public function testThePendingActionsMfaDoesNotTakeAreLeftOut(): void
    {
        $actions = [
            AuthenticationPendingAction::LIST_PRINCIPALS,
            AuthenticationPendingAction::VERIFY,
            AuthenticationPendingAction::CHOOSE_PRINCIPAL,
            AuthenticationPendingAction::LIST_FACTORS,
        ];

        self::assertSame([MfaPendingAction::VERIFY, MfaPendingAction::LIST_FACTORS], (new ChangeTranslator)->pendingActions($actions));
        self::assertSame([], (new ChangeTranslator)->pendingActions([AuthenticationPendingAction::CHOOSE_PRINCIPAL]));
    }
}
