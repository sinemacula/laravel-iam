<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

use SineMacula\Laravel\Authentication\Sessions\SignInResult;

/**
 * Thrown when `laravel-authentication` refuses the external sign-in a `sign_in`
 * handoff code SSO admitted was redeemed for (IAM-4.1).
 *
 * A refusal by `laravel-authentication` (`sso_required`, `method_not_allowed`,
 * `external_result_unlinked`, `link_mismatch` or any other) is thrown out of
 * the redemption's transaction, so SSO's consumption of the code, a
 * reservation's activation and the connection's completed sign-in are rolled
 * back with it, and nothing reports a sign-in that did not happen: the code
 * stays unspent until it expires. The failed result is carried as
 * `laravel-authentication` answered it, for the application to answer the
 * client from once the transaction has rolled back.
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

        /** The failed sign-in, as laravel-authentication answered it. */
        public readonly SignInResult $result,
    ) {
        parent::__construct($message);
    }

    /**
     * Build an exception for the failed sign-in, naming its reason.
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
