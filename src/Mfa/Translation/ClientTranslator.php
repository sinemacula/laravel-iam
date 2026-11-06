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
 * Both describe a client by the same five facts: its IP address and user agent,
 * and the facts a cookie application's same-site check judges (the `Origin`
 * presented, the request's own scheme and host, and the names of the headers it
 * carried with a value, lower-cased with underscores read as hyphens). MFA
 * cleans the last three as `laravel-authentication` does, so each crosses one
 * to one, either way. Towards `laravel-authentication`, it makes the IP address
 * and user agent safe to store as it does any client's (an IP address that is
 * not one is dropped, a user agent cleaned and cut); towards MFA, they cross as
 * `laravel-authentication` kept them. The client is the one the member hands
 * over, judged and recorded by the other as given: nothing is read from a
 * request, and no fact the member does not carry is invented. A client MFA does
 * not hand over is one of which nothing is known, which a cookie application's
 * same-site check refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ClientTranslator
{
    /**
     * MFA's client as `laravel-authentication`'s: its IP address, user agent,
     * `Origin`, scheme and host, and the names of the headers it carried with a
     * value, each as MFA carries it.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    public static function toAuthentication(MfaClient $client): AuthenticationClient
    {
        return new AuthenticationClient($client->ip, $client->userAgent, $client->origin, $client->schemeAndHost, $client->nonEmptyHeaders);
    }

    /**
     * `laravel-authentication`'s client as MFA's: its IP address, user agent,
     * `Origin`, scheme and host, and the names of the headers it carried with a
     * value, each as `laravel-authentication` carries it.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Mfa\Context\ClientContext
     */
    public static function toMfa(AuthenticationClient $client): MfaClient
    {
        return new MfaClient($client->ip, $client->userAgent, $client->origin, $client->schemeAndHost, $client->nonEmptyHeaders);
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
