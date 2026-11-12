<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * A `laravel-authentication` session as MFA names a sign-in, binding the proofs
 * read from it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignIn
{
    /** @var string The sign-in bound when no session is named; the colon keeps it from matching a session key. */
    public const string UNNAMED = 'iam:unnamed-session';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  int  $generation
     */
    public function __construct(

        /** The identity that signed in. */
        public ProofOwner $identity,

        /** The application (the guard's name) it signed in on. */
        public string $application,

        /** The session's key, as MFA names the sign-in. */
        public string $session,

        /** The identity's MFA verification generation the proofs are stamped with. */
        public int $generation,
    ) {}

    /**
     * The session's key as a string, the reference MFA names it by.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $application
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public static function reference(Session $session, string $application): string
    {
        $key = $session->getSessionIdentifier();

        if ((!is_string($key) && !is_int($key)) || $key === '') {
            throw UnresolvedReferenceException::forSession($application);
        }

        return (string) $key;
    }

    /**
     * The binding of a proof of the sign-in made for the purpose.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     *
     * @throws \InvalidArgumentException
     */
    public function binding(Purpose $purpose): ProofBinding
    {
        return new ProofBinding($this->identity->type, $this->identity->key, $this->application, $this->session, $purpose);
    }
}
