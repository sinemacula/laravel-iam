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
            . ' each application MFA verifies further factors for, or SSO signs people in to, is a guard of the jwt driver, named the same.';

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
     * `laravel-authentication`'s `Identity` contract.
     *
     * @param  string  $type
     * @return self
     */
    public static function forIdentity(string $type): self
    {
        return new self(sprintf('The identity of type [%s] cannot be resolved: it must implement laravel-authentication\'s Identity contract.', $type), ReferenceKind::IDENTITY);
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

    /**
     * Build an exception for an identity SSO names by reference that cannot be
     * resolved to `laravel-authentication`'s identity: its type names, through
     * the morph map, no Eloquent model implementing the `Identity` contract, no
     * stored identity holds its id, or the one found is named another way. The
     * id is left out of the message, as any identifier of a person is.
     *
     * @param  string  $type
     * @return self
     */
    public static function forIdentityReference(string $type): self
    {
        $message = 'The identity SSO names, of type [%s], cannot be resolved: its type must name, through the morph map, an Eloquent model'
            . ' implementing laravel-authentication\'s Identity contract, whose morph class it is, and its id the key of one stored.';

        return new self(sprintf($message, $type), ReferenceKind::IDENTITY);
    }

    /**
     * Build an exception for a tenant SSO names by its opaque id that
     * `laravel-authentication`'s tenant resolver resolves to no tenant, or to
     * one with another identifier, so the sessions acting in it cannot be
     * judged.
     *
     * @param  string  $tenantId
     * @return self
     */
    public static function forTenant(string $tenantId): self
    {
        $message = 'The tenant [%s] cannot be resolved: laravel-authentication\'s tenant resolver must resolve it to the tenant whose identifier it is,'
            . ' so the sessions acting in it can be judged; the change is refused rather than left unenforced.';

        return new self(sprintf($message, $tenantId), ReferenceKind::TENANT);
    }

    /**
     * Build an exception for a tenant a grant that widens an identity's scope
     * holds in that `laravel-authentication`'s tenant resolver resolves to no
     * tenant, or to one of another type or identifier, so the widening cannot
     * be reported to SSO for it.
     *
     * @param  string  $tenantId
     * @return self
     */
    public static function forGrantTenant(string $tenantId): self
    {
        $message = 'The tenant [%s] a grant holds in cannot be resolved: laravel-authentication\'s tenant resolver must resolve it to the tenant of its type'
            . ' whose identifier it is, so the widening of the identity\'s scope can be reported to laravel-sso; the grant is refused rather than written unreported.';

        return new self(sprintf($message, $tenantId), ReferenceKind::TENANT);
    }

    /**
     * Build an exception for a tenant `laravel-authentication` asks about whose
     * identifier is neither a non-empty string nor an integer, so it cannot be
     * named to the member that answers for it.
     *
     * @return self
     */
    public static function forTenantIdentifier(): self
    {
        $message = 'The tenant cannot be named by its identifier: a tenant\'s identifier must be a non-empty string or an integer,'
            . ' so its authentication policy can be asked; the session is refused rather than judged against no policy.';

        return new self($message, ReferenceKind::TENANT);
    }
}
