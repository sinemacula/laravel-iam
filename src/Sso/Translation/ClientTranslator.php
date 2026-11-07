<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso\Translation;

use SineMacula\Laravel\Authentication\Http\ClientContext as AuthenticationClient;
use SineMacula\Laravel\Sso\Http\ClientContext as SsoClient;

/**
 * Translates the client a redemption is made for from
 * `laravel-authentication`'s client context to SSO's, the one place the two
 * members' client contexts meet.
 *
 * SSO describes a client by two of the facts `laravel-authentication` does: its
 * IP address and its user agent, which it makes safe to keep under the rules
 * `laravel-authentication` applies to the same two values, and which every
 * attempt SSO counts and every event it reports carries. So the redemption is
 * handed one client, `laravel-authentication`'s, and SSO is handed the same IP
 * address and user agent: nothing is read from a request, and no fact the
 * caller did not hand over is invented. The facts only a cookie application's
 * same-site check judges stay with `laravel-authentication`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ClientTranslator
{
    /**
     * `laravel-authentication`'s client as SSO's: its IP address and user
     * agent, as `laravel-authentication` carries them.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Http\ClientContext
     */
    public static function toSso(AuthenticationClient $client): SsoClient
    {
        return new SsoClient($client->ip, $client->userAgent);
    }
}
