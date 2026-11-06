<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;

/**
 * Thrown when an adapter needs a tenant, an identity, a principal, a session or
 * the guard an application names, and it cannot be resolved (IAM-8.2).
 *
 * It is thrown inside the transaction the member opened, so whatever the member
 * was changing rolls back: no adapter answers a security question with a guess,
 * so one that cannot find what the question is about refuses it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class UnresolvedReferenceException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  \SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind  $kind
     * @param  ?string  $application
     */
    public function __construct(

        // What could not be resolved, and why.
        string $message,

        /** What could not be resolved. */
        public readonly ReferenceKind $kind,

        /** The application (the guard) it was looked for on, when there is one. */
        public readonly ?string $application = null,
    ) {
        parent::__construct($message);
    }

    /**
     * Build an exception for an application that names no guard of
     * `laravel-authentication`'s holding sessions, so no session of it can be
     * resolved: a misconfiguration, told apart from a guard that merely holds
     * no session now.
     *
     * @param  string  $application
     * @return self
     */
    public static function forGuard(string $application): self
    {
        $message = 'The application [%s] is not a laravel-authentication guard that holds sessions, so no session of it can be resolved:'
            . ' each MFA application that verifies further factors is a guard of the jwt driver, named the same.';

        return new self(sprintf($message, $application), ReferenceKind::GUARD, $application);
    }

    /**
     * Build an exception for a guard that holds no current session of the
     * identity asked about: none is bound to it, or the one bound is another
     * identity's.
     *
     * @param  string  $application
     * @return self
     */
    public static function forSession(string $application): self
    {
        $message = 'The guard [%s] holds no current session of the identity asked about, so the sign-in MFA names cannot be resolved;'
            . ' the change is refused rather than made against no session.';

        return new self(sprintf($message, $application), ReferenceKind::SESSION, $application);
    }

    /**
     * Build an exception for a sign-in MFA names that is no session of the
     * identity asked about on the guard: no session holds its key, or the one
     * that does is another identity's or another guard's.
     *
     * @param  string  $application
     * @return self
     */
    public static function forSignIn(string $application): self
    {
        $message = 'The sign-in MFA names is no session of the identity asked about on the guard [%s], so it cannot be resolved;'
            . ' the change is refused rather than made against another session or none.';

        return new self(sprintf($message, $application), ReferenceKind::SESSION, $application);
    }

    /**
     * Build an exception for an identity that does not implement
     * `laravel-authentication`'s `Identity` contract, so it is not one
     * `laravel-authentication` signs in, or whose key is neither a non-empty
     * string nor an integer, so nothing it proved can be found.
     *
     * @param  string  $type
     * @return self
     */
    public static function forIdentity(string $type): self
    {
        $message = 'The identity of type [%s] cannot be resolved: it must implement laravel-authentication\'s Identity contract,'
            . ' and its key must be a non-empty string or an integer.';

        return new self(sprintf($message, $type), ReferenceKind::IDENTITY);
    }

    /**
     * Build an exception for an identity `laravel-authentication` signs in that
     * does not implement MFA's `MultiFactorAuthenticatable` contract, so MFA
     * holds no factors for it and nothing it must prove can be judged.
     *
     * @param  string  $type
     * @return self
     */
    public static function forMfaIdentity(string $type): self
    {
        $message = 'The identity of type [%s] cannot be resolved for MFA: it must implement laravel-mfa\'s MultiFactorAuthenticatable contract,'
            . ' which the HasFactors trait provides, so MFA can hold its factors.';

        return new self(sprintf($message, $type), ReferenceKind::IDENTITY);
    }
}
