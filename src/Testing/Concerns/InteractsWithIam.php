<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Concerns;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Testing\Concerns\InteractsWithAuthenticationContext;
use SineMacula\Laravel\Iam\Testing\VerifiedSession;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;

/**
 * Act across the suite in a Laravel test, with this package's adapters bound.
 *
 * With this package's proof store bound, a session's proofs are the ones
 * `laravel-authentication` records and a proof counts only while it names one
 * of the identity's factors, so MFA's `InteractsWithMfa::actingAsVerified()`,
 * which records synthetic proofs through the store, is refused with MFA's
 * `ProofRefusedException`. `actingOnVerifiedSession()` arranges the same thing
 * the way a real step-up does: it acts on the session, as
 * `laravel-authentication`'s `actingOnSession()` does, enrols a confirmed
 * fixture factor for the session's identity and steps the session up with a
 * proof made with it, then reads the proofs back as MFA's route gate does and
 * throws a `LogicException` unless they evaluate at exactly the level asked
 * for, with additional verification. The session must be a live, active session
 * of a person, signed in as the application signs people in, so it holds its
 * first factor.
 *
 * Acting composes with `laravel-authentication`'s helpers, which this trait
 * brings in: the same context authenticates every request the test then sends
 * through the HTTP kernel, until the test acts again or stops acting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait InteractsWithIam
{
    use InteractsWithAuthenticationContext;

    /**
     * Act on the session, on the guard it records (or the guard given, or the
     * default guard), verified now at exactly the level with additional
     * verification.
     *
     * The further proof is made now and the session's first factor when it
     * signed in, so a test of freshness verifies the session and then moves the
     * clock on (`$this->travel(20)->minutes()`), rather than verifying it in
     * the past. Each call enrols a further confirmed factor for the session's
     * identity: an email factor for AAL1, an authenticator app for AAL2, and a
     * passkey for AAL3, which needs a combination policy that rates a
     * hardware-protected passkey AAL3. The unclassified level is refused with
     * an `InvalidArgumentException` before anything is recorded.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  ?string  $guard
     * @return static
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function actingOnVerifiedSession(EloquentSession&Model $session, AssuranceLevel $level = AssuranceLevel::AAL2, ?string $guard = null): static
    {
        $this->actingOnSession($session, $guard);

        Container::getInstance()->make(VerifiedSession::class)->verify($level);

        return $this;
    }
}
