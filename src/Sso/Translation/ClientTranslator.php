<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso\Translation;

use SineMacula\Laravel\Authentication\Http\ClientContext as AuthenticationClient;
use SineMacula\Laravel\Sso\Http\ClientContext as SsoClient;

/**
 * Translates `laravel-authentication`'s client context into SSO's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ClientTranslator
{
    /**
     * `laravel-authentication`'s client as SSO's: its IP and user agent.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Http\ClientContext
     */
    public static function toSso(AuthenticationClient $client): SsoClient
    {
        return new SsoClient($client->ip, $client->userAgent);
    }
}
