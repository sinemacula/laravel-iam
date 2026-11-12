<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

/**
 * Thrown when SSO admits a sign-in handoff linked to no identity; the
 * redemption rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class UnlinkedSignInException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  string  $application
     * @param  string  $connectionId
     */
    public function __construct(

        // What was refused, naming the application and the connection.
        string $message,

        /** The application the code was redeemed for. */
        public readonly string $application,

        /** The connection the code was redeemed through. */
        public readonly string $connectionId,
    ) {
        parent::__construct($message);
    }

    /**
     * Build an exception naming neither the code nor the result's subject.
     *
     * @param  string  $application
     * @param  string  $connectionId
     * @return self
     */
    public static function forConnection(string $application, string $connectionId): self
    {
        $message = 'SSO admitted a sign-in for the application [%s] through the connection [%s] that is linked to no identity:'
            . ' the redemption is rolled back, since only a linked result signs anyone in.';

        return new self(sprintf($message, $application, $connectionId), $application, $connectionId);
    }
}
