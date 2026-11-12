<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authorization\Contracts\ScopeRegistry as AuthorizationScopeRegistry;
use SineMacula\Laravel\Authorization\Support\CatalogueScopeRegistry;

/**
 * Rejects a credential scope `laravel-authorization`'s scope registry does not
 * accept, so a credential names only real permissions.
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
     * The scopes `laravel-authorization`'s registry does not accept.
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
     * The bound scope registry, else `laravel-authorization`'s shipped one.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\ScopeRegistry
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function registry(): AuthorizationScopeRegistry
    {
        // `laravel-authorization` ships `CatalogueScopeRegistry` unbound.
        $abstract = $this->container->bound(AuthorizationScopeRegistry::class) ? AuthorizationScopeRegistry::class : CatalogueScopeRegistry::class;

        /** @var \SineMacula\Laravel\Authorization\Contracts\ScopeRegistry */
        return $this->container->make($abstract);
    }
}
