<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\ExternalSignInRefusedException;
use SineMacula\Laravel\Iam\Exceptions\UnlinkedSignInException;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Provisioning\GroupGrants;
use SineMacula\Laravel\Iam\Provisioning\GroupSettings;
use SineMacula\Laravel\Iam\Sso\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Redeems a `sign_in` handoff code and signs the linked identity in, in one
 * transaction on the storage connection retried whole.
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
     * @param  \SineMacula\Laravel\Iam\Provisioning\GroupSettings  $groups
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     */
    public function __construct(

        /** Resolves SSO's redemption and the request's records on each call. */
        private Container $container,

        /** Runs the redemption in one transaction on the storage connection, retried whole. */
        private CrossMemberTransaction $transaction,

        /** Finds the session service of the guard the application is. */
        private CurrentSession $sessions,

        /** Finds the application's group re-sync, if it opts into one. */
        private GroupSettings $groups,

        /** Resolves the identity the result links, for its re-sync. */
        private IdentityReferences $identities,
    ) {}

    /**
     * Redeem the `sign_in` code, answering SSO's refusal or the sign-in.
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
        // Wrapped so no trace of a throw inside holds the secrets in the clear.
        $secrets = new \SensitiveParameterValue([$code, $verifier]);

        [$result, $resynced] = $this->transaction->run(function () use ($application, $connectionId, $secrets, $context): array {

            $admitted = $this->container->make(AdmittedRedemptions::class);

            $admitted->forget();

            try {
                [$code, $verifier] = $secrets->getValue();

                return $this->signIn($admitted, $application, $connectionId, $code, $verifier, $context);
            } finally {
                $admitted->forget();
            }
        });

        // After the commit: scope widening takes the identity's guard, which
        // SSO orders before the connection held here.
        if ($resynced !== null) {
            $this->resync($resynced);
        }

        return $result;
    }

    /**
     * Admit the code and sign in the identity it links.
     *
     * @param  \SineMacula\Laravel\Iam\Sso\AdmittedRedemptions  $admitted
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return array{\SineMacula\Laravel\Authentication\Sessions\SignInResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult, ?\SineMacula\Laravel\Sso\Handoffs\RedemptionResult}
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
    ): array {
        $sessions   = $this->sessions->sessions($application);
        $ssoClient  = ClientTranslator::toSso($context->client);
        $redemption = $this->container->make(HandoffRedemption::class)
            ->admit(Purpose::SIGN_IN, $application, $connectionId, $code, $verifier, $ssoClient);

        if (!$redemption->isRedeemed()) {
            return [$redemption, null];
        }

        if ($redemption->linkedIdentity === null) {
            throw UnlinkedSignInException::forConnection($application, $connectionId);
        }

        $admitted->record($redemption, $ssoClient);

        $signIn = $sessions->signInExternally(ExternalResults::from($redemption), $context);

        return $signIn->isFailed() ? throw ExternalSignInRefusedException::for($signIn) : [$signIn, $redemption];
    }

    /**
     * Re-sync the linked identity's groups, when the application opts in.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function resync(RedemptionResult $redemption): void
    {
        $resync = $this->groups->resync();

        if ($resync === null) {
            return;
        }

        $result = self::verified($redemption);
        $linked = self::linked($redemption);

        $this->transaction->run(fn () => $resync->resync($this->identities->identity($linked), $result->connectionId, $result->tenantId, GroupGrants::groupsOf($result)));
    }

    /**
     * The identity the redemption links.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     *
     * @throws \LogicException
     */
    private static function linked(RedemptionResult $redemption): IdentityReference
    {
        return $redemption->linkedIdentity ?? throw new \LogicException('A redemption signed in links the identity it signs in.');
    }

    /**
     * The verified result the redemption carries.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \LogicException
     */
    private static function verified(RedemptionResult $redemption): VerifiedResult
    {
        return $redemption->result ?? throw new \LogicException('A redeemed sign-in carries the result it redeemed.');
    }
}
