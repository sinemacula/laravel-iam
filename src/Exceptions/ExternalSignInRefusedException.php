<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

use SineMacula\Laravel\Authentication\Sessions\SignInResult;

/**
 * Thrown when laravel-authentication refuses the sign-in an SSO handoff code
 * was redeemed for; the redemption rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class ExternalSignInRefusedException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     */
    public function __construct(

        // What was refused, and why.
        string $message,

        /** The failed result, for the application to answer the client from. */
        public readonly SignInResult $result,
    ) {
        parent::__construct($message);
    }

    /**
     * Build an exception naming the result's reason.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return self
     */
    public static function for(SignInResult $result): self
    {
        $message = 'laravel-authentication refused the external sign-in [%s]: the redemption is rolled back, and the handoff code stays unspent.';

        return new self(sprintf($message, $result->reason->value ?? $result->status->value), $result);
    }
}
