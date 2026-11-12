<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkEmailQuery;

/**
 * SSO's link email contract, answered from the identities' verified email
 * addresses through `laravel-authentication`'s email normaliser (IAM-4.7,
 * SSO-8.8, AUTH-3.1).
 *
 * The email SSO asserts is passed, exactly as asserted, through the normaliser
 * `laravel-authentication` registers for the `email` identifier type
 * (`IdentifierNormalizers::get('email')`), the one its identifier cast stores
 * an identity's email in, and nothing more is done to it: no subaddress or dot
 * removal, no Unicode folding and no confusable matching. An email the
 * normaliser refuses names nobody. Every identity model a session guard of
 * `laravel-authentication`'s signs in (the `model` of each `jwt` guard's
 * provider) that can report its identifiers' verification is searched for that
 * normal form, on the write connection with the model's own query, its global
 * scopes kept, so a hidden or deleted identity never matches; the identifier is
 * the attribute named after its type, as `ProvidesIdentifierVerification` keeps
 * it. A row counts only when the identity reports its email address verified
 * and that address is the normal form byte for byte, so neither a merely
 * present address nor one a case- or accent-insensitive collation matched
 * counts. One identity counting is `exactly one`; none is `none`; more than one
 * is `ambiguous`, which SSO refuses, never a guess between them.
 *
 * SSO asks it by a plain read before its completion's locks, again under them,
 * and again inside the redeemer's transaction, and the answer must stay true
 * until that commits. It takes no lock: locking the rows it found would not
 * stop another identity from verifying the same address later. It relies on the
 * application's guarantee that one verified email address belongs to one
 * identity (a unique index on the email column, which the identifier cast's one
 * normal form makes exact), or on a guard every writer of a verified email
 * takes after SSO's locks, in SSO's order. The tenant SSO names is not
 * consulted: which identities may link through a tenant's connection is link
 * eligibility's and tenant membership's to judge (IAM-7.4).
 *
 * The email is never logged, nor put in an exception's message; an error
 * propagates, since an answer it cannot vouch for is never `exactly one`. It
 * keeps nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkEmailMatcherAdapter implements LinkEmailMatcher
{
    /** @var string The identifier type of an email address, which names its normaliser, its attribute and its verification. */
    private const string EMAIL = 'email';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers  $normalizers
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     */
    public function __construct(

        /** `laravel-authentication`'s identifier normalisers. */
        private IdentifierNormalizers $normalizers,

        /** The configuration the guards' providers are declared in. */
        private Repository $config,

        /** Names a matching identity as SSO names it. */
        private IdentityReferences $identities,
    ) {}

    /**
     * The identities whose verified email address is the query's, in its normal
     * form.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\LinkEmailQuery  $query
     * @return \SineMacula\Laravel\Sso\Linking\LinkEmailMatch
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function match(LinkEmailQuery $query): LinkEmailMatch
    {
        $email = $this->normalizers->get(self::EMAIL)->normalize($query->email());

        if ($email === null) {
            return LinkEmailMatch::none();
        }

        $matched = [];

        foreach ($this->models() as $model) {
            foreach ($this->verified($model, $email) as $identity) {
                $matched[] = $identity;
            }
        }

        return match (count($matched)) {
            0       => LinkEmailMatch::none(),
            1       => LinkEmailMatch::exactlyOne($matched[0]),
            default => LinkEmailMatch::ambiguous(),
        };
    }

    /**
     * The identities of the model's whose email address is verified and is the
     * normal form byte for byte, read on the write connection.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity  $model
     * @param  string  $email
     * @return list<\SineMacula\Laravel\Sso\Identities\IdentityReference>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function verified(HasVerifiableIdentifiers&Identity&Model $model, #[\SensitiveParameter] string $email): array
    {
        $identities = $this->identities;

        /** @var list<\SineMacula\Laravel\Sso\Identities\IdentityReference> */
        return WriteConnection::during($model, static function () use ($model, $email, $identities): array {

            $found = [];

            foreach (WriteConnection::query($model->newQuery())->where(self::EMAIL, $email)->get() as $candidate) {

                if (!self::holdsVerified($candidate, $email)) {
                    continue;
                }

                $found[] = $identities->reference($candidate);
            }

            return $found;
        });
    }

    /**
     * Whether the identity's email address is the normal form byte for byte,
     * and verified.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers  $identity
     * @param  string  $email
     * @return bool
     */
    private static function holdsVerified(HasVerifiableIdentifiers $identity, #[\SensitiveParameter] string $email): bool
    {
        return $identity->getIdentifierForVerification(self::EMAIL) === $email && $identity->hasVerifiedIdentifier(self::EMAIL);
    }

    /**
     * A blank instance of each identity model a session guard signs in, once
     * each, that can report its identifiers' verification, in the order the
     * guards are declared.
     *
     * @return list<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity>
     */
    private function models(): array
    {
        $models = [];

        foreach (Auth::sessionGuards() as $guard) {

            $provider = $this->config->get('auth.guards.' . $guard . '.provider');
            $class    = is_string($provider) ? $this->config->get('auth.providers.' . $provider . '.model') : null;

            if (!self::isVerifiableIdentity($class) || isset($models[$class])) {
                continue;
            }

            $models[$class] = new $class;
        }

        return array_values($models);
    }

    /**
     * Whether the class is an Eloquent identity model that can report its
     * identifiers' verification.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  mixed  $class
     * @return bool
     *
     * @phpstan-assert-if-true class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity> $class
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function isVerifiableIdentity(mixed $class): bool
    {
        return is_string($class)
            && is_a($class, Model::class, true)
            && is_a($class, Identity::class, true)
            && is_a($class, HasVerifiableIdentifiers::class, true);
    }
}
