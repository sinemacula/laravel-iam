<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Resolvers\IdentityReferences as AuthenticationIdentityReferences;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Translates between SSO's identity references and `laravel-authentication`'s
 * Eloquent identities through the morph map.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentityReferences
{
    /**
     * The identity the reference names exactly; anything else throws.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $reference
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function identity(IdentityReference $reference): Identity&Model
    {
        return AuthenticationIdentityReferences::resolve($reference->type, $reference->id)
            ?? throw UnresolvedReferenceException::forIdentityReference($reference->type);
    }

    /**
     * Whether the type names an Eloquent model implementing `Identity`.
     *
     * @param  string  $type
     * @return bool
     */
    public function namesIdentity(string $type): bool
    {
        $class = Relation::getMorphedModel($type) ?? $type;

        return is_a($class, Model::class, true) && is_a($class, Identity::class, true);
    }

    /**
     * The reference SSO names the identity by: its morph class and its key.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function reference(Identity $identity): IdentityReference
    {
        if (!$identity instanceof Model) {
            throw UnresolvedReferenceException::forIdentity($identity::class);
        }

        $key = $identity->getKey();

        if ((!is_string($key) && !is_int($key)) || $key === '') {
            throw UnresolvedReferenceException::forIdentity($identity::class);
        }

        return new IdentityReference($identity->getMorphClass(), (string) $key);
    }
}
