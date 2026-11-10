<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;

/**
 * A tenant of a second type, an account an application keeps below its
 * organisations: `laravel-authentication`'s tenant, naming itself by its id,
 * and `laravel-authorization`'s, named by a morph type of its own and that same
 * id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Account implements AuthorizableTenant, Tenant
{
    /** @var string The morph type `laravel-authorization` names an account by. */
    public const string TYPE = 'account';

    /** @var string The prefix every account's id begins with. */
    public const string PREFIX = 'account-';

    /**
     * Constructor.
     *
     * @param  string  $id
     */
    public function __construct(

        /** The account's id. */
        private string $id,
    ) {}

    /**
     * The account's id, as `laravel-authentication` records it on a session.
     *
     * @return string
     */
    #[\Override]
    public function getTenantIdentifier(): string
    {
        return $this->id;
    }

    /**
     * The account's key, as `laravel-authorization` names it: its id.
     *
     * @return string
     */
    #[\Override]
    public function getKey(): string
    {
        return $this->id;
    }

    /**
     * The morph type `laravel-authorization` names an account by.
     *
     * @return string
     */
    #[\Override]
    public function getMorphClass(): string
    {
        return self::TYPE;
    }
}
