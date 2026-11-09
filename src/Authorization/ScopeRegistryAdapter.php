<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authorization\Contracts\ScopeRegistry as AuthorizationScopeRegistry;
use SineMacula\Laravel\Authorization\Support\CatalogueScopeRegistry;

/**
 * `laravel-authentication`'s scope registry (AUTH-4.5), answered from
 * `laravel-authorization`'s (AUTHZ-13.5, IAM-6.5), so a credential is issued
 * only scopes that name real permissions: every scope `laravel-authorization`'s
 * registry does not accept is rejected, and `laravel-authentication` then
 * refuses to issue or rotate the credential.
 *
 * `laravel-authorization`'s registry is the application's binding of its
 * contract where it binds one, and otherwise the registry
 * `laravel-authorization` ships for it and binds nowhere
 * (`CatalogueScopeRegistry`): every scope the scope map
 * (`authorization.session.scopes`) names, and every other scope that names a
 * permission the catalogue declares, or a pattern covering one. It is resolved
 * afresh on every call, since the shipped one holds the scope map, which
 * `laravel-authorization` builds once a request or job, so no request's map
 * reaches another (IAM-8.1).
 *
 * What a scope means is `laravel-authorization`'s to say: the registry is asked
 * about each scope alone, as its contract asks it, and neither the guard nor
 * the principal changes the answer. Whatever the registry throws (a permission
 * catalogue `laravel-authorization` refuses) propagates, so no credential is
 * issued that the registry could not judge.
 *
 * It holds nothing between calls, so it is bound transient.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ScopeRegistryAdapter implements ScopeRegistry
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves `laravel-authorization`'s scope registry. */
        private Container $container,
    ) {}

    /**
     * The scopes, of those given, `laravel-authorization`'s registry does not
     * accept, in the order given; `[]` when it accepts them all.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  list<string>  $scopes
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function rejected(string $guard, Principal $principal, array $scopes): array
    {
        $registry = $this->registry();

        return array_values(array_filter($scopes, static fn (string $scope): bool => !$registry->isValid($scope)));
    }

    /**
     * `laravel-authorization`'s scope registry: the application's binding of
     * its contract, or the one `laravel-authorization` ships for it.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\ScopeRegistry
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function registry(): AuthorizationScopeRegistry
    {
        $abstract = $this->container->bound(AuthorizationScopeRegistry::class) ? AuthorizationScopeRegistry::class : CatalogueScopeRegistry::class;

        /** @var \SineMacula\Laravel\Authorization\Contracts\ScopeRegistry */
        return $this->container->make($abstract);
    }
}
