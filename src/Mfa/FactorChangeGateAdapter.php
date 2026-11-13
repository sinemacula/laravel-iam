<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict;
use SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;

/**
 * MFA's factor-change gate, judged by `laravel-authentication`'s gate on the
 * session MFA names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorChangeGateAdapter implements FactorChangeGate
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator  $changes
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator  $requirements
     */
    public function __construct(

        /** Resolves the sign-in the change is made from to its session, and the guard's session service. */
        private CurrentSession $sessions,

        /** Translates MFA's change to `laravel-authentication`'s. */
        private ChangeTranslator $changes,

        /** Translates the requirement MFA's application configures for the change. */
        private RequirementTranslator $requirements,
    ) {}

    /**
     * Allow the change, returning when the session stops being fresh for it.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function authorize(FactorChangeRequest $request): CarbonImmutable
    {
        $session     = $this->sessions->named($request->identity, $request->application, $request->session);
        $requirement = $request->requirement === null ? null : $this->requirements->toFreshness($request->requirement);

        $service = $this->sessions->sessions($request->application);
        $verdict = $service->factorChange($session, $this->changes->factorChange($request->change), $requirement, $request->factorId);

        return self::allowedUntil($verdict, $request);
    }

    /**
     * When the allowed verdict stays fresh; a refused one throws `not_fresh`.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict  $verdict
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return \Carbon\CarbonImmutable
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function allowedUntil(FactorChangeVerdict $verdict, FactorChangeRequest $request): CarbonImmutable
    {
        $until = $verdict->freshUntil;

        if ($until !== null) {
            return $until;
        }

        $detail = sprintf('laravel-authentication refused the change [%s] from the session: [%s].', $request->change->value, $verdict->reason->value ?? '');

        throw new OperationRefusedException(FailureReason::NOT_FRESH, $detail);
    }
}
