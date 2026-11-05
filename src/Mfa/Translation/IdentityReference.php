<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * An identity as MFA names it on a proof's binding: its type (its morph class
 * for an Eloquent identity, so the application's morph map is honoured, and its
 * class name otherwise) and its key as a string.
 *
 * It follows the rule MFA records its own proofs' owners by, which MFA keeps
 * internal, so a proof translated from `laravel-authentication`'s is owned by
 * exactly the identity MFA's own checks look for. A key that is neither a
 * non-empty string nor an integer would let distinct identities meet on one
 * reference, so it is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentityReference
{
    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  string  $key
     */
    private function __construct(

        /** The identity's type: its morph class, or its class name. */
        public string $type,

        /** The identity's key, as a string. */
        public string $key,
    ) {}

    /**
     * The reference MFA names the identity by.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return self
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public static function of(Authenticatable $identity): self
    {
        $key = $identity->getAuthIdentifier();

        if ((!is_string($key) && !is_int($key)) || $key === '') {
            throw UnresolvedReferenceException::forIdentity($identity::class);
        }

        // @phpstan-ignore staticMethod.dynamicCall
        $type = $identity instanceof Model ? $identity->getMorphClass() : $identity::class;

        return new self($type, (string) $key);
    }

    /**
     * Whether the other reference names the same identity.
     *
     * @param  self  $other
     * @return bool
     */
    public function is(self $other): bool
    {
        return $this->type === $other->type && $this->key === $other->key;
    }

    /**
     * Whether MFA's proof binding names this identity as the proof's owner.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     */
    public function owns(ProofBinding $binding): bool
    {
        return $this->type === $binding->identityType && $this->key === $binding->identityKey;
    }
}
