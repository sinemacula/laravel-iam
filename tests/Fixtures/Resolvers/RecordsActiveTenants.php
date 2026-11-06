<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Resolvers;

use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * An active tenant resolver that answers as the one it wraps does, and records
 * every answer, in the order given.
 *
 * It stands between MFA and the active tenant adapter, so a test can show that
 * MFA asked the adapter on a path, and what it was told, without changing the
 * answer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordsActiveTenants implements ActiveTenantResolver
{
    /** @var list<?string> The answers given, in the order given. */
    public array $answers = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver  $resolver
     */
    public function __construct(

        /** The resolver whose answers are recorded. */
        private readonly ActiveTenantResolver $resolver,
    ) {}

    /**
     * The wrapped resolver's answer, recorded.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     */
    #[\Override]
    public function activeTenant(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        $tenant = $this->resolver->activeTenant($identity, $application);

        $this->answers[] = $tenant;

        return $tenant;
    }
}
