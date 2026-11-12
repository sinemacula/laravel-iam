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
 * SSO's link email matcher, answered from the identities whose verified email
 * is the asserted address in `laravel-authentication`'s normal form.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkEmailMatcherAdapter implements LinkEmailMatcher
{
    /** @var string The `email` identifier type, which also names its attribute. */
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
     * The identities whose verified email is the query's normal form.
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
     * The model's identities holding the verified email byte for byte.
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

            // laravel-authentication has no lookup by verified identifier.
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
     * Whether the identity holds the email, byte for byte and verified.
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
     * A blank instance of each verifiable identity model a guard signs in.
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
     * Whether the class is an Eloquent identity that reports verification.
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
