<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;

/**
 * An organisation whose key differs from its identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RekeyedOrganisation implements AuthorizableTenant, Tenant
{
    /**
     * Constructor.
     *
     * @param  string  $key
     * @param  string  $identifier
     */
    public function __construct(

        /** The organisation's key. */
        private string $key,

        /** The organisation's identifier. */
        private string $identifier,
    ) {}

    /**
     * The organisation's identifier, as recorded on a session.
     *
     * @return string
     */
    #[\Override]
    public function getTenantIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * The organisation's key, as `laravel-authorization` keys its grants.
     *
     * @return string
     */
    #[\Override]
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * The morph type `laravel-authorization` names an organisation by.
     *
     * @return string
     */
    #[\Override]
    public function getMorphClass(): string
    {
        return Organisation::TYPE;
    }
}
