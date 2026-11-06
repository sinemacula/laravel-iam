<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Delivery\Enums;

/**
 * The way a code reaches its recipient, and so the gateway that delivers it:
 * the application's email gateway or its SMS gateway (IAM-3.13). The values are
 * the gateway names `iam.delivery.types` maps an identifier type to.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Channel: string
{
    // An email address, through the application's `EmailGateway`
    case EMAIL = 'email';

    // An E.164 phone number, through the application's `SmsGateway`
    case SMS = 'sms';
}
