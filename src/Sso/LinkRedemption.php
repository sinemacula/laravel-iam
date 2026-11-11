<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Sso\Translation\ClientTranslator;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;

/**
 * Redeems a `link` handoff code as the caller through SSO's own redemption,
 * which opens its own transaction, so a concurrency failure is the caller's to
 * retry (IAM-4.3, IAM-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class LinkRedemption
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Sso\Callers  $callers
     */
    public function __construct(

        /** Resolves SSO's redemption on each call. */
        private Container $container,

        /** Names the caller as SSO takes it. */
        private Callers $callers,
    ) {}

    /**
     * Redeem the `link` code for the caller's application through the
     * connection, and answer SSO's result.
     *
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Callers\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function redeem(
        string $connectionId,
        #[\SensitiveParameter] string $code,
        #[\SensitiveParameter] string $verifier,
        ClientContext $client,
        Caller $caller,
    ): RedemptionResult {
        $named = $this->callers->of($caller);

        return $this->container->make(HandoffRedemption::class)->redeem(
            Purpose::LINK,
            $caller->guard,
            $connectionId,
            $code,
            $verifier,
            ClientTranslator::toSso($client),
            $named,
        );
    }
}
