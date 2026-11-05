<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions\Enums;

/**
 * What an adapter needed to resolve and could not: a tenant, an identity, a
 * principal, a session, or the guard an application names (IAM-8.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
enum ReferenceKind: string
{
    // A tenant the members name by its opaque id
    case TENANT = 'tenant';

    // The identity a member asks about
    case IDENTITY = 'identity';

    // The principal an identity acts as
    case PRINCIPAL = 'principal';

    // A sign-in, as one member names another's session
    case SESSION = 'session';

    // The guard an application names, which must hold sessions
    case GUARD = 'guard';
}
