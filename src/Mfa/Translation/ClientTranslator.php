<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

use SineMacula\Laravel\Authentication\Http\ClientContext as AuthenticationClient;
use SineMacula\Laravel\Mfa\Context\ClientContext as MfaClient;

/**
 * Translates the client an action is served to between MFA and
 * `laravel-authentication`, the one place the two members' client contexts
 * meet.
 *
 * MFA's client is its IP address and user agent alone; `laravel-authentication`'s
 * also carries the facts a cookie application's same-site check judges (the
 * `Origin` presented, the request's own scheme and host, and the names of the
 * headers it carried). MFA's client crosses with its IP address and user agent,
 * which `laravel-authentication` makes safe to store as it does any client's
 * (an IP address that is not one is dropped, a user agent cleaned and cut), and
 * with none of those facts, since MFA keeps none: the client is
 * `laravel-authentication`'s to describe the action by (its last use, its
 * events, its limits on an IP address), never to pass a same-site check by. A
 * client MFA does not hand over is one of which nothing is known.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ClientTranslator
{
    /**
     * MFA's client as `laravel-authentication`'s: its IP address and user
     * agent, with no same-site facts.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    public static function toAuthentication(MfaClient $client): AuthenticationClient
    {
        return new AuthenticationClient($client->ip, $client->userAgent);
    }

    /**
     * `laravel-authentication`'s client of which nothing is known, for an
     * action MFA hands no client with.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    public static function unknown(): AuthenticationClient
    {
        return self::toAuthentication(MfaClient::unknown());
    }
}
