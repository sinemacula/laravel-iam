<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

/**
 * Thrown when the application boots with this package's pending completion
 * bound and a session guard whose refresh token travels in a cookie, where no
 * pending sign-in could ever be completed through MFA.
 *
 * `laravel-authentication`'s `satisfy()` refuses a cookie application's client
 * that carries no same-site facts as `cross_site_request`, before it reads the
 * pending session, and MFA hands its pending completion no client, so the
 * completion can hand `satisfy()` none that passes. Rather than refuse every
 * such sign-in at the moment a person proves their further factor, the
 * application is refused when it boots.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class CookieTransportUnsupportedException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  string  $guard
     */
    public function __construct(

        // What cannot be served, naming the guard.
        string $message,

        /** The session guard whose refresh token travels in a cookie. */
        public readonly string $guard,
    ) {
        parent::__construct($message);
    }

    /**
     * Build an exception for a session guard whose refresh token travels in a
     * cookie while this package's pending completion is bound, naming the guard
     * and what the application can do.
     *
     * @param  string  $guard
     * @return self
     */
    public static function forPendingCompletion(string $guard): self
    {
        $message = 'The guard [%s] carries its refresh token in a cookie, so no pending sign-in on it can be completed through MFA:'
            . ' MFA hands the pending completion no client, and laravel-authentication refuses a cookie application\'s pending session'
            . ' for a client that carries no same-site facts as [cross_site_request]. Carry the guard\'s refresh token in the body,'
            . ' bind your own SineMacula\Laravel\Mfa\Contracts\PendingCompletion, or turn iam.adapters.mfa off.';

        return new self(sprintf($message, $guard), $guard);
    }
}
