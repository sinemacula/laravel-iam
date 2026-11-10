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
 * Translates between the identities SSO names by reference and
 * `laravel-authentication`'s identities, through the application's morph map.
 *
 * SSO names an identity by an opaque reference, a type and an id; for an
 * Eloquent identity the type is its morph class and the id its key, which is
 * how `laravel-authentication` records a session's owner too. So a reference is
 * resolved (`identity()`) to the Eloquent model its type names through the
 * morph map (or, with no entry, as a class name), when that model implements
 * `laravel-authentication`'s `Identity` contract, read by its key on the write
 * connection with the model's own query, as `laravel-authentication`'s model
 * provider reads an identity, and only when the identity found is named by
 * exactly that reference, as `reference()` names it: a model of a mapped class
 * named by its class name is another reference, and never stands in for it, and
 * nor does a key the database matches to an id that is not its own byte for
 * byte (another case or trailing spaces under a case- or pad-insensitive
 * collation, an upper-case UUID), since SSO keys its records by those bytes and
 * would hold it as another identity. An id that cannot be a key of the model is
 * not queried. Anything else throws `UnresolvedReferenceException` (IAM-8.2),
 * inside whatever transaction SSO opened, so the change it was making rolls
 * back; nothing is guessed. Whether a type can name such an identity at all is
 * asked apart (`namesIdentity()`), by a caller that passes over a reference of
 * any other kind rather than refuse it.
 *
 * The other way (`reference()`), an Eloquent identity is named by its morph
 * class and its key as a string, which SSO compares byte for byte. Only an
 * Eloquent identity can be named: no other could be resolved back, and
 * `laravel-authentication` records the owner of a session only for one.
 *
 * It keeps nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentityReferences
{
    /**
     * The identity the reference names.
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
        $found = SessionKeyShape::matches($blank, $reference->id) ? self::find($blank, $reference->id) : null;

        if (!$found instanceof Identity || !self::namedBy($found, $reference)) {
            throw UnresolvedReferenceException::forIdentityReference($reference->type);
        }

        return $found;
    }

    /**
     * Whether the type names, through the morph map or as a class name, an
     * Eloquent model implementing `laravel-authentication`'s `Identity`
     * contract: the only kind of identity a reference of it can resolve to.
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
     * Whether the class is an Eloquent model implementing
     * `laravel-authentication`'s `Identity` contract.
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
     * Whether the reference names the identity exactly as `reference()` names
     * it: its morph class is the type, and its key, as a string, the id byte
     * for byte, whatever the database's collation matched.
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
     * The stored model holding the key, read on the write connection with the
     * model's own query, or `null` when none does.
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
