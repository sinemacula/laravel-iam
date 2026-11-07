<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\ExternalSignInRefusedException;
use SineMacula\Laravel\Iam\Exceptions\UnlinkedSignInException;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Sso\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;

/**
 * Redeems a `sign_in` handoff code SSO issued, and signs the person it links in
 * through `laravel-authentication`, in one transaction (IAM-4.1, AUTH-3.10,
 * AUTH-5.3, SSO-9.2).
 *
 * The transaction is opened on the storage connection, the one Laravel
 * connection SSO's and `laravel-authentication`'s storage settings both name,
 * through the retry helper (IAM-11.2), so a serialisation failure, a deadlock
 * or SSO's `LinkCandidatesChanged` runs the whole of it again, and only when it
 * opened the outermost transaction. In it, in this order:
 *
 * 1. the application is resolved to its guard, which must be one of
 *    `laravel-authentication`'s guards holding sessions, or an
 *    `UnresolvedReferenceException` rolls the redemption back before the code
 *    is touched (IAM-8.2);
 * 2. SSO admits the code (`HandoffRedemption::admit()`), taking its locks in
 *    its order; its refusal is answered as the redemption's result, and
 *    commits, so the code is spent and one `FlowFailed` follows the commit;
 * 3. an admitted result that links no identity throws
 *    `UnlinkedSignInException`, rolling the consumption back (SSO-8.6);
 * 4. the admitted redemption is recorded for this request, with the client SSO
 *    was handed for it, so `laravel-authentication`'s link contract answers
 *    exactly the link it resolved, and SSO's exemption gate, should the tenant
 *    policy ask it, is handed this sign-in's client (`AdmittedRedemptions`);
 * 5. `laravel-authentication` signs the person in once, on the guard, with the
 *    result built from the redemption alone (`ExternalResults::from()`) and the
 *    context the caller handed over, the redemption's session deadline capping
 *    the session; its session writes come after every lock SSO took, so the
 *    session's row is the last lock. A failed sign-in throws
 *    `ExternalSignInRefusedException`, rolling the consumption back: the code
 *    stays unspent and nothing reports a sign-in that did not happen. A pending
 *    session is a success, and commits.
 *
 * The admitted redemption is forgotten as each attempt starts and ends, so a
 * retried attempt never answers from one rolled back. What it answers leaves
 * only once the transaction has committed, so a credential is never handed out
 * for a session that rolled back; the application sends it with
 * `Cache-Control: no-store`.
 *
 * It is handed plain values alone: the code, the verifier, the application, the
 * connection and the context of the client the redemption is made for, which
 * the application builds where it reads the request
 * (`SignInContext::fromRequest()`), or builds of a client of which nothing is
 * known from a job or a command. It reads no request itself. SSO's redemption
 * and the request's records are resolved on each call, so it keeps nothing of
 * one redemption for the next.
 *
 * The code and the verifier are handed to the transaction's work wrapped in a
 * `SensitiveParameterValue`, and unwrapped only inside it, so the trace of
 * anything thrown there, whose frames carry the work and what it captured,
 * never holds either in the clear.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class SignInRedemption
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction  $transaction
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     */
    public function __construct(

        /** Resolves SSO's redemption and the request's records on each call. */
        private Container $container,

        /** Runs the redemption in one transaction on the storage connection, retried whole. */
        private CrossMemberTransaction $transaction,

        /** Finds the session service of the guard the application is. */
        private CurrentSession $sessions,
    ) {}

    /**
     * Redeem the `sign_in` code for the application through the connection,
     * with its verifier, for the client the context names, and answer SSO's
     * refusal, committed, or the sign-in, active or pending.
     *
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnlinkedSignInException
     * @throws \SineMacula\Laravel\Iam\Exceptions\ExternalSignInRefusedException
     * @throws \Throwable
     */
    public function redeem(
        string $application,
        string $connectionId,
        #[\SensitiveParameter] string $code,
        #[\SensitiveParameter] string $verifier,
        SignInContext $context,
    ): RedemptionResult|SignInResult {
        $secrets = new \SensitiveParameterValue([$code, $verifier]);

        return $this->transaction->run(function () use ($application, $connectionId, $secrets, $context): RedemptionResult|SignInResult {

            $admitted = $this->container->make(AdmittedRedemptions::class);

            $admitted->forget();

            try {
                [$code, $verifier] = $secrets->getValue();

                return $this->signIn($admitted, $application, $connectionId, $code, $verifier, $context);
            } finally {
                $admitted->forget();
            }
        });
    }

    /**
     * Admit the code, then sign the person it links in, inside the redemption's
     * transaction.
     *
     * @param  \SineMacula\Laravel\Iam\Sso\AdmittedRedemptions  $admitted
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnlinkedSignInException
     * @throws \SineMacula\Laravel\Iam\Exceptions\ExternalSignInRefusedException
     */
    private function signIn(
        AdmittedRedemptions $admitted,
        string $application,
        string $connectionId,
        #[\SensitiveParameter] string $code,
        #[\SensitiveParameter] string $verifier,
        SignInContext $context,
    ): RedemptionResult|SignInResult {
        $sessions   = $this->sessions->sessions($application);
        $ssoClient  = ClientTranslator::toSso($context->client);
        $redemption = $this->container->make(HandoffRedemption::class)
            ->admit(Purpose::SIGN_IN, $application, $connectionId, $code, $verifier, $ssoClient);

        if (!$redemption->isRedeemed()) {
            return $redemption;
        }

        if ($redemption->linkedIdentity === null) {
            throw UnlinkedSignInException::forConnection($application, $connectionId);
        }

        $admitted->record($redemption, $ssoClient);

        $signIn = $sessions->signInExternally(ExternalResults::from($redemption), $context);

        return $signIn->isFailed() ? throw ExternalSignInRefusedException::for($signIn) : $signIn;
    }
}
