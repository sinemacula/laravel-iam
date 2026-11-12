<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authorization\Services\ApplicationAccess as AuthorizationApplicationAccess;

/**
 * Answers `laravel-authentication`'s application access from
 * `laravel-authorization`'s grants, in the principal's own tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApplicationAccessAdapter implements ApplicationAccess
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authorization\Services\ApplicationAccess  $access
     */
    public function __construct(

        /** Decides whether a principal may use an application from its grants. */
        private AuthorizationApplicationAccess $access,
    ) {}

    /**
     * Whether the principal's grants allow it to use the application.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    #[\Override]
    public function mayUse(string $application, Principal $principal): bool
    {
        return $this->access->mayUse($application, $principal, $principal->getTenant());
    }
}
