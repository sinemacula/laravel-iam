<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

/**
 * One grant an identity provider's groups give a person (IAM-7.2): a role,
 * named as `laravel-authorization` names it, granted to the identity itself in
 * the tenant of the connection the groups came through, and, when
 * `$includeSubtree` says so, in every tenant below it in the tenant tree.
 *
 * It names no tenant of its own: a connection's groups never grant beyond the
 * connection's tenant and its subtree, whatever the mapping answers, and never
 * platform-wide. It names no application either, so the grant holds in every
 * application, nor an expiry, so it holds until a re-sync, or the application,
 * revokes it. The role is looked up as `laravel-authorization` looks up a name,
 * among the roles visible in the tenant; a name it does not find refuses the
 * grant.
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
