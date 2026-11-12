<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

/**
 * Thrown when the sign-in a member names is another session than the guard's
 * current one; the change rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class SessionMismatchException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  string  $application
     */
    public function __construct(

        // What differs, naming the guard.
        string $message,

        /** The guard whose current session is another. */
        public readonly string $application,
    ) {
        parent::__construct($message);
    }

    /**
     * Build an exception naming the guard but neither session.
     *
     * @param  string  $application
     * @return self
     */
    public static function forGuard(string $application): self
    {
        $message = 'The sign-in MFA names is not the current session of the guard [%s]:'
            . ' the change is refused rather than judged against another session.';

        return new self(sprintf($message, $application), $application);
    }
}
