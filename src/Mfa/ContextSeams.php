<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;

/**
 * The seams MFA reads its context through; the active tenant's is mandatory
 * while tenant MFA is enforced or required.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ContextSeams implements ProvidesSeams
{
    /**
     * Constructor.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Tells whether the application binds MFA's tenant requirement; with none, only the configuration is read. */
        private ?Container $container = null,
    ) {}

    /**
     * Return the bindings of MFA's context.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $on       = MfaSeams::isOn($config);
        $enforced = fn (): bool => TenancySeams::isEnforcedOrRequired($config, $this->container);

        return [
            new SeamBinding(EventContextResolver::class, EventContextResolverAdapter::class, $on),
            new SeamBinding(ActiveTenantResolver::class, ActiveTenantResolverAdapter::class, $on, mandatory: $enforced),
            new SeamBinding(SubjectTypeResolver::class, SubjectTypeResolverAdapter::class, $on),
            new SeamBinding(ActiveStateResolver::class, ActiveStateResolverAdapter::class, $on),
            new SeamBinding(ApplicationResolver::class, ApplicationResolverAdapter::class, $on),
        ];
    }
}
