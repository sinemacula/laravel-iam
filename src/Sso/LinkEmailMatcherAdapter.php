<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Facades\Auth;
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
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     */
    public function __construct(

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
        $matched = [];

        foreach ($this->models() as $model) {
            foreach ($model::holdingVerifiedIdentifier(self::EMAIL, $query->email()) as $identity) {
                $matched[] = $this->identities->reference($identity);
            }
        }

        return match (count($matched)) {
            0       => LinkEmailMatch::none(),
            1       => LinkEmailMatch::exactlyOne($matched[0]),
            default => LinkEmailMatch::ambiguous(),
        };
    }

    /**
     * Each verifiable identity model a guard signs in.
     *
     * @return list<class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity>>
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

            $models[$class] = $class;
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
