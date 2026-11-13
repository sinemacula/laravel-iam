<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

use SineMacula\Laravel\Authentication\Http\ClientContext as AuthenticationClient;
use SineMacula\Laravel\Mfa\Context\ClientContext as MfaClient;

/**
 * Translates the client an action is served to between MFA and
 * `laravel-authentication`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ClientTranslator
{
    /**
     * MFA's client as `laravel-authentication`'s.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    public static function toAuthentication(MfaClient $client): AuthenticationClient
    {
        return new AuthenticationClient($client->ip, $client->userAgent, $client->origin, $client->schemeAndHost, $client->nonEmptyHeaders);
    }

    /**
     * `laravel-authentication`'s client as MFA's.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Mfa\Context\ClientContext
     */
    public static function toMfa(AuthenticationClient $client): MfaClient
    {
        return new MfaClient($client->ip, $client->userAgent, $client->origin, $client->schemeAndHost, $client->nonEmptyHeaders);
    }

    /**
     * A client of which nothing is known.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    public static function unknown(): AuthenticationClient
    {
        return self::toAuthentication(MfaClient::unknown());
    }
}
