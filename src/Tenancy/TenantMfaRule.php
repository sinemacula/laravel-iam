<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;

/**
 * The application's answer for one tenant (IAM-4.5): the further factors a
 * session acting in it must have, as `laravel-authentication`'s requirement,
 * and the version of that answer.
 *
 * The version names the answer, so it changes whenever the requirement does;
 * it is 1 to `TenantRequirement::VERSION_MAX_LENGTH` (64) characters, the
 * longest version a session records, or `null` for an answer that cannot be
 * versioned, which is never taken as already checked. An empty requirement asks
 * for nothing (`none()`).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TenantMfaRule
{
    /** @var int The longest version a rule carries, the longest a session records. */
    public const int VERSION_MAX_LENGTH = TenantRequirement::VERSION_MAX_LENGTH;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  ?string  $version
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The further factors a session acting in the tenant must have; an empty requirement asks for none. */
        public Requirement $requirement,

        /** The version of the answer, 1 to 64 characters, or `null`. */
        public ?string $version = null,
    ) {
        if ($version !== null && ($version === '' || mb_strlen($version) > self::VERSION_MAX_LENGTH)) {
            throw new \InvalidArgumentException(sprintf('A tenant MFA rule\'s version must be between 1 and %d characters.', self::VERSION_MAX_LENGTH));
        }
    }

    /**
     * A rule that requires nothing of the tenant's sessions.
     *
     * @param  ?string  $version
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function none(?string $version = null): self
    {
        return new self(new Requirement, $version);
    }

    /**
     * Whether the rule requires nothing.
     *
     * @return bool
     */
    public function isEmpty(): bool
    {
        return $this->requirement->isEmpty();
    }
}
