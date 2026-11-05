<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * One of `laravel-authentication`'s sessions as MFA names a sign-in: the
 * identity, the application (the guard's name), the session's key as a string
 * and the identity's MFA verification generation when its proofs are read.
 *
 * `laravel-authentication`'s recorded proofs carry no binding of their own, so
 * a proof read from a session is bound here: MFA counts a proof only for its
 * own identity, application and sign-in, and only under the identity's current
 * verification generation, which the adapter reads and hands in, since reading
 * it is a query and translation is not. Where `laravel-authentication` names no
 * session, every proof of one judgement is bound to the same sign-in
 * (`UNNAMED`), as MFA counts only the proofs of one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignIn
{
    /** @var string The sign-in a proof is bound to when `laravel-authentication` names no session (at sign-in, and when it asks for a requirement): a reference no session key can be, as it holds a colon, so no adapter that reads a session's proofs ever produces it. */
    public const string UNNAMED = 'iam:unnamed-session';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  int  $generation
     */
    public function __construct(

        /** The identity that signed in. */
        public IdentityReference $identity,

        /** The application (the guard's name) it signed in on. */
        public string $application,

        /** The session's key, as MFA names the sign-in. */
        public string $session,

        /** The identity's MFA verification generation the proofs are stamped with. */
        public int $generation,
    ) {}

    /**
     * The reference MFA names a session by: its key, which is always its
     * primary key, as a string. A key that is neither a non-empty string nor an
     * integer names no session MFA could refer back to.
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
     * The binding MFA reads a proof of the sign-in made for the given purpose
     * as bound to.
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
