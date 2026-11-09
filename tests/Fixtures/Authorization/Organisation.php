<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;

/**
 * A tenant both `laravel-authentication` and `laravel-authorization` read:
 * `laravel-authentication`'s tenant, naming itself by its id, and
 * `laravel-authorization`'s, named by its morph type and that same id, as an
 * application's tenant model is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Organisation implements AuthorizableTenant, Tenant
{
    /** @var string The morph type `laravel-authorization` names an organisation by. */
    public const string TYPE = 'organisation';

    /**
     * Constructor.
     *
     * @param  string  $id
     */
    public function __construct(

        /** The organisation's id. */
        private string $id,
    ) {}

    /**
     * The organisation's id, as `laravel-authentication` records it on a
     * session.
     *
     * @return string
     */
    #[\Override]
    public function getTenantIdentifier(): string
    {
        return $this->id;
    }

    /**
     * The organisation's id, as `laravel-authorization` keys its grants.
     *
     * @return string
     */
    #[\Override]
    public function getKey(): string
    {
        return $this->id;
    }

    /**
     * The morph type `laravel-authorization` names an organisation by.
     *
     * @return string
     */
    #[\Override]
    public function getMorphClass(): string
    {
        return self::TYPE;
    }
}
