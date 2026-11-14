<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation;
use SineMacula\Laravel\Iam\Exceptions\ExternalReauthenticationRefusedException;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Sso\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;

/**
 * Redeems a `reauthenticate` handoff code and renews the session it names with
 * one write, in one transaction on the storage connection retried whole.
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
     * @param  \SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation  $decisions
     */
    public function __construct(

        /** Resolves SSO's redemption and the request's records on each call. */
        private Container $container,

        /** Runs the redemption in one transaction on the storage connection, retried whole. */
        private CrossMemberTransaction $transaction,

        /** Finds the session service of the guard the application is. */
        private CurrentSession $sessions,

        /** Forgets the decisions that read the renewed session's authentication. */
        private DecisionCacheInvalidation $decisions,
    ) {}

    /**
     * Redeem the `reauthenticate` code, answering SSO's refusal or the token.
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
        // Wrapped so no trace of a throw inside holds the secrets in the clear.
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
     * Admit the code, renew the session and forget the decisions that read it.
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
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
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

        if ($token->isFailed()) {
            throw ExternalReauthenticationRefusedException::for($token);
        }

        $this->decisions->authenticationChanged($renewal->identity, $renewal->sessionId);

        return $token;
    }
}
