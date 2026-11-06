<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Iam\Exceptions\ExternalReauthenticationRefusedException;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Sso\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;

/**
 * Redeems a `reauthenticate` handoff code SSO issued, and renews the session it
 * names through `laravel-authentication`, with exactly one write, in one
 * transaction (IAM-4.2, AUTH-3.11, SSO-9.5).
 *
 * The transaction is opened on the storage connection through the retry helper
 * (IAM-11.2), as a sign-in's is. In it, in this order:
 *
 * 1. the application is resolved to its guard, which must be one of
 *    `laravel-authentication`'s guards holding sessions, or an
 *    `UnresolvedReferenceException` rolls the redemption back before the code
 *    is touched (IAM-8.2);
 * 2. SSO admits the code (`HandoffRedemption::admit()`), taking its locks in
 *    its order, then asking its reauthentication sessions contract for the
 *    session's locked standing (its row locked last) and to renew it, which the
 *    adapter records and does not write (`RenewalRecorder`); SSO's refusal is
 *    answered as the redemption's result, and commits, so the code is spent;
 * 3. the admitted redemption is recorded for this request, so
 *    `laravel-authentication`'s link contract answers exactly the link it
 *    resolved (`AdmittedRedemptions`);
 * 4. the renewal recorded is taken, and must be the one session the redemption
 *    names: none, or another session, is a `LogicException`;
 * 5. `laravel-authentication` re-authenticates that session once, on the guard,
 *    with the result built from the redemption and the renewal
 *    (`ExternalResults::renewing()`): the one write, `auth_time` becoming the
 *    later of the session's and the provider's under the session's lock, and
 *    the only token issued. It takes no lock after that. A failed access token
 *    result throws `ExternalReauthenticationRefusedException`, rolling the
 *    consumption back, so nothing reports a renewal that did not happen;
 * 6. a renewal still recorded when the transaction is about to commit, one SSO
 *    asked for and the redemption never wrote, is a `LogicException`, and rolls
 *    back.
 *
 * `laravel-authentication`'s external re-authentication is never called when
 * SSO refused, or when SSO recorded no renewal, and the session's time is
 * written nowhere else. Both records are forgotten as each attempt starts and
 * ends, so a retried attempt never meets the renewal of one rolled back, and
 * the renewal recorder is open only while an attempt runs, so a renewal SSO
 * asks for outside one (a `reauthenticate` code admitted through SSO's own
 * `admit()`) is a `LogicException` that rolls that admission back: a
 * `reauthenticate` code is redeemed through this service alone. The access
 * token leaves only once the transaction has committed; the application sends
 * it with `Cache-Control: no-store`.
 *
 * It is handed plain values alone: the code, the verifier, the application, the
 * connection and the client the redemption is made for, which the application
 * builds where it reads the request (`ClientContext::fromRequest()`), or as a
 * client of which nothing is known from a job or a command. The session is the
 * one the code names, never the one a request is authenticated with. SSO's
 * redemption and the request's records are resolved on each call.
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
final readonly class ReauthenticationRedemption
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
     * Redeem the `reauthenticate` code for the application through the
     * connection, with its verifier, for the client, and answer SSO's refusal,
     * committed, or the access token issued for the renewed session.
     *
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Iam\Exceptions\ExternalReauthenticationRefusedException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function redeem(
        string $application,
        string $connectionId,
        #[\SensitiveParameter] string $code,
        #[\SensitiveParameter] string $verifier,
        ClientContext $client,
    ): AccessTokenResult|RedemptionResult {
        $secrets = new \SensitiveParameterValue([$code, $verifier]);

        return $this->transaction->run(function () use ($application, $connectionId, $secrets, $client): AccessTokenResult|RedemptionResult {

            $admitted = $this->container->make(AdmittedRedemptions::class);
            $recorder = $this->container->make(RenewalRecorder::class);

            $admitted->forget();
            $recorder->open();

            try {
                [$code, $verifier] = $secrets->getValue();

                $answer = $this->reauthenticate($admitted, $recorder, $application, $connectionId, $code, $verifier, $client);

                if ($recorder->isHolding()) {
                    throw new \LogicException('A re-authentication commits with its one renewal written: a renewal SSO asked for is still recorded.');
                }

                return $answer;
            } finally {
                $admitted->forget();
                $recorder->close();
            }
        });
    }

    /**
     * Admit the code, then renew the session the renewal recorded, inside the
     * redemption's transaction.
     *
     * @param  \SineMacula\Laravel\Iam\Sso\AdmittedRedemptions  $admitted
     * @param  \SineMacula\Laravel\Iam\Sso\RenewalRecorder  $recorder
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\ExternalReauthenticationRefusedException
     *
     * @SuppressWarnings("php:S107")
     */
    private function reauthenticate(
        AdmittedRedemptions $admitted,
        RenewalRecorder $recorder,
        string $application,
        string $connectionId,
        #[\SensitiveParameter] string $code,
        #[\SensitiveParameter] string $verifier,
        ClientContext $client,
    ): AccessTokenResult|RedemptionResult {
        $sessions   = $this->sessions->sessions($application);
        $redemption = $this->container->make(HandoffRedemption::class)
            ->admit(Purpose::REAUTHENTICATE, $application, $connectionId, $code, $verifier, ClientTranslator::toSso($client));

        if (!$redemption->isRedeemed()) {
            return $redemption;
        }

        $admitted->record($redemption);

        $renewal = $recorder->take() ?? throw new \LogicException('SSO admitted a re-authentication without asking for its renewal.');

        if ($renewal->sessionId !== $redemption->sessionId) {
            throw new \LogicException('A re-authentication renews the session its code names: SSO asked to renew another.');
        }

        $token = $sessions->reauthenticateExternally($renewal->sessionId, ExternalResults::renewing($redemption, $renewal), $client);

        return $token->isFailed() ? throw ExternalReauthenticationRefusedException::for($token) : $token;
    }
}
