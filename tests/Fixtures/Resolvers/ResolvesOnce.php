<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Resolvers;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;

/**
 * A tenant resolver that resolves the first identifier it is asked for to a
 * tenant of that identifier, and throws the failure it was given every time
 * after, so an enforcement change's first pass resolves the enforcing tenant
 * and its second pass fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResolvesOnce implements TenantResolver
{
    /** @var int How many times a tenant has been asked for. */
    private int $asked = 0;

    /**
     * Constructor.
     *
     * @param  \RuntimeException  $failure
     */
    public function __construct(

        /** What every resolution after the first throws. */
        private readonly \RuntimeException $failure,
    ) {}

    /**
     * Resolve the identifier the first time, and throw every time after.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function resolve(string $tenantId): Tenant
    {
        if ($this->asked++ > 0) {
            throw $this->failure;
        }

        return new ClaimedTenant($tenantId);
    }
}
