<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Delivery\Enums;

/**
 * The member a code came from: `laravel-authentication`, whose codes sign
 * people in, verify and change identifiers, reset passwords and, on MFA's
 * behalf, challenge and enrol factors; or MFA, when it delivers its own codes
 * through its senders.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Source: string
{
    // `laravel-authentication`'s one-time code sender
    case AUTHENTICATION = 'authentication';

    // MFA's SMS and email senders
    case MFA = 'mfa';
}
