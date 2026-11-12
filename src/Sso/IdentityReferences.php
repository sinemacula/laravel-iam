<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\SessionRecords\SessionKeyShape;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
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
        $class = self::classOf($reference->type);

        if (!self::isIdentityModel($class)) {
            throw UnresolvedReferenceException::forIdentityReference($reference->type);
        }

        $blank = new $class;
        // laravel-authentication lacks a public key-shape check.
        $found = SessionKeyShape::matches($blank, $reference->id) ? self::find($blank, $reference->id) : null;

        if (!$found instanceof Identity || !self::namedBy($found, $reference)) {
            throw UnresolvedReferenceException::forIdentityReference($reference->type);
        }

        return $found;
    }

    /**
     * Whether the type names an Eloquent model implementing `Identity`.
     *
     * @param  string  $type
     * @return bool
     */
    public function namesIdentity(string $type): bool
    {
        return self::isIdentityModel(self::classOf($type));
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

    /**
     * The class the type names: its morph map entry, or the type itself.
     *
     * @param  string  $type
     * @return string
     */
    private static function classOf(string $type): string
    {
        return Relation::getMorphedModel($type) ?? $type;
    }

    /**
     * Whether the class is an Eloquent model implementing `Identity`.
     *
     * @param  string  $class
     * @return bool
     *
     * @phpstan-assert-if-true class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity> $class
     */
    private static function isIdentityModel(string $class): bool
    {
        return is_a($class, Model::class, true) && is_a($class, Identity::class, true);
    }

    /**
     * Whether the reference names the identity byte for byte.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $reference
     * @return bool
     */
    private static function namedBy(Model $identity, IdentityReference $reference): bool
    {
        return $identity->getMorphClass() === $reference->type && IdentifierCoercion::stringify($identity->getKey()) === $reference->id;
    }

    /**
     * The model holding the key, read on the write connection.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $blank
     * @param  string  $id
     * @return ?\Illuminate\Database\Eloquent\Model
     */
    private static function find(Model $blank, string $id): ?Model
    {
        return WriteConnection::during($blank, static fn (): ?Model => WriteConnection::query($blank->newQuery())->find($id));
    }
}
