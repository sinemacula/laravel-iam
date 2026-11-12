<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions\Enums;

/**
 * What an adapter needed to resolve and could not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
enum ReferenceKind: string
{
    case TENANT    = 'tenant';
    case IDENTITY  = 'identity';
    case PRINCIPAL = 'principal';
    case SESSION   = 'session';
    case GUARD     = 'guard';
}
