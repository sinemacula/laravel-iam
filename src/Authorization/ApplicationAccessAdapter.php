<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authorization\Services\ApplicationAccess as AuthorizationApplicationAccess;

/**
 * `laravel-authentication`'s application access contract (AUTH-2.11), answered
 * from `laravel-authorization`'s grants (AUTHZ-13.4, IAM-6.6): a principal may
 * use an application that `authorization.application_access` maps to a
 * permission only while its grants on that application allow the permission,
 * and any application the map does not name, as `laravel-authentication`'s
 * default admits.
 *
 * `laravel-authorization` decides it (`Services\ApplicationAccess`), about the
 * principal handed in, in the principal's own tenant (`null` for a platform
 * principal), on the application asked about: neither the request's caller nor
 * its tenant, since a sign-in, a switch or a refresh asks about a principal
 * that is not yet, or no longer, the request's. The principal becomes the
 * check's subject through the bound subject resolver's `forUser()`, which reads
 * no caller, so a guard asking while it admits its request is never entered
 * again. `laravel-authentication` asks it inside `WriteConnection::during()`
 * for the principal, so the principal's tenant and grants are read from the
 * primary. Whatever the decision throws propagates, and
 * `laravel-authentication` admits nothing it could not ask about.
 *
 * `laravel-authorization` decides the access without session caps, since a
 * principal being admitted holds no session yet: neither the request's
 * credential scopes nor a machine's missing ones refuse it, so a machine is
 * admitted on its grants as a person is, while a deny, a boundary or a
 * guardrail still refuses. An application the map leaves out is open to every
 * principal, people included, whatever their grants.
 *
 * It keeps nothing itself, but is bound scoped (under `iam.scoped:`), as
 * IAM-6.6 asks, so a long-running worker builds it afresh for each request or
 * job and forgets it with `Iam::resetWorkerState()`.
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
     * Whether the principal may use the application, as its grants on it allow,
     * in its own tenant.
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
