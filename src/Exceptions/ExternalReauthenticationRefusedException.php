<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;

/**
 * Thrown when `laravel-authentication` refuses the external re-authentication a
 * `reauthenticate` handoff code SSO admitted was redeemed for (IAM-4.2).
 *
 * A failed access token result (`link_mismatch`, `sso_required`,
 * `additional_factor_required` or any other) is thrown out of the redemption's
 * transaction, so SSO's consumption of the code rolls back with it, and nothing
 * reports a renewal that did not happen. The failed result is carried as
 * `laravel-authentication` answered it, for the application to answer the
 * client from once the transaction has rolled back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class ExternalReauthenticationRefusedException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult  $result
     */
    public function __construct(

        // What was refused, and why.
        string $message,

        /** The failed access token result, as laravel-authentication answered it. */
        public readonly AccessTokenResult $result,
    ) {
        parent::__construct($message);
    }

    /**
     * Build an exception for the failed re-authentication, naming its reason.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult  $result
     * @return self
     */
    public static function for(AccessTokenResult $result): self
    {
        $message = 'laravel-authentication refused the external re-authentication [%s]: the redemption is rolled back, and the handoff code stays unspent.';

        return new self(sprintf($message, $result->reason->value ?? 'failed'), $result);
    }
}
