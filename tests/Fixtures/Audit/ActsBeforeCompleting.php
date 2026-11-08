<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Audit;

use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Iam\Mfa\StepUpAdapter;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * MFA's step-up and pending completion as this package's adapters make them,
 * after running the change it is given first: inside MFA's transaction, once
 * MFA has accepted the proof and before `laravel-authentication` locks the
 * session, as a change another request commits at that moment would land.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ActsBeforeCompleting implements PendingCompletion, StepUp
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\StepUpAdapter  $stepUp
     * @param  \SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter  $completion
     * @param  \Closure(): void  $change
     */
    public function __construct(

        /** The step-up this package binds. */
        private StepUpAdapter $stepUp,

        /** The pending completion this package binds. */
        private PendingCompletionAdapter $completion,

        /** The change made before either is handed the proof. */
        private \Closure $change,
    ) {}

    /**
     * Make the change, then step the caller's session up as the adapter does.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    #[\Override]
    public function stepUp(CallerContext $caller, VerificationResult $result): AccessTokenResult
    {
        ($this->change)();

        return $this->stepUp->stepUp($caller, $result);
    }

    /**
     * Make the change, then satisfy the caller's pending session as the adapter
     * does.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    #[\Override]
    public function complete(CallerContext $caller, VerificationResult $result): SignInResult
    {
        ($this->change)();

        return $this->completion->complete($caller, $result);
    }
}
