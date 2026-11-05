<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

/**
 * Thrown when the sign-in a member names is not the current session of the
 * guard it is on: the identity is signed in there, but the change is about
 * another of its sessions.
 *
 * It is thrown inside the transaction the member opened, so the change rolls
 * back rather than being committed against a session nobody judged.
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

        /** The application (the guard) whose current session is another. */
        public readonly string $application,
    ) {
        parent::__construct($message);
    }

    /**
     * Build an exception for a sign-in that is not the guard's current session,
     * naming the guard but neither session.
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
