<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;

/**
 * Thrown when laravel-authentication refuses the re-authentication an SSO
 * handoff code was redeemed for; the redemption rolls back.
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

        /** The failed result, for the application to answer the client from. */
        public readonly AccessTokenResult $result,
    ) {
        parent::__construct($message);
    }

    /**
     * Build an exception naming the result's reason.
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
