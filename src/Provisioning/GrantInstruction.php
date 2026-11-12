<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

/**
 * A role an identity provider's groups grant in the connection's tenant, and
 * optionally its subtree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class GrantInstruction
{
    /** @var int The most bytes a role's name may hold, as `laravel-authorization` stores it. */
    public const int MAX_ROLE_LENGTH = 191;

    /**
     * Constructor.
     *
     * @param  string  $role
     * @param  bool  $includeSubtree
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The role granted, by its name. */
        public string $role,

        /** Whether the grant holds in the tenants below the connection's tenant too. */
        public bool $includeSubtree = false,
    ) {
        if (trim($role) === '' || strlen($role) > self::MAX_ROLE_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A grant instruction names its role by a non-blank name of at most %d bytes.', self::MAX_ROLE_LENGTH));
        }
    }

    /**
     * The role, granted in the connection's tenant alone.
     *
     * @param  string  $role
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function role(string $role): self
    {
        return new self($role);
    }

    /**
     * The role, granted in the connection's tenant and every tenant below it.
     *
     * @param  string  $role
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function roleWithSubtree(string $role): self
    {
        return new self($role, true);
    }
}
