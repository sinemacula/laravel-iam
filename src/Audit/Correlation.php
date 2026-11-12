<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use SineMacula\Laravel\AuditLog\Records\CorrelationId;

/**
 * The correlation ids the mappers tie the members' records together with
 * (IAM-9.5), one namespace per source; a missing part, or an id audit-log would
 * refuse, is no id, so a record is never lost to the refusal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Correlation
{
    /** @var string The namespace of one SSO sign-in. */
    public const string SSO = 'sso';

    /** @var string The namespace of an MFA challenge. */
    public const string MFA = 'mfa';

    /** @var string The namespace of a challenge of `laravel-authentication`'s own. */
    public const string AUTHENTICATION = 'authentication';

    /** @var string The namespace of a session's events. */
    public const string SESSION = 'session';

    /** @var string The namespace of one `laravel-authorization` management call. */
    public const string AUTHORIZATION = 'authorization';

    /**
     * One SSO sign-in, by its connection and the public reference of its
     * authorisation request.
     *
     * @param  ?string  $connectionId
     * @param  ?string  $requestReference
     * @return ?string
     */
    public static function ssoSignIn(?string $connectionId, ?string $requestReference): ?string
    {
        return self::id(self::SSO, $connectionId, $requestReference);
    }

    /**
     * An MFA challenge, by its id.
     *
     * @param  ?string  $challengeId
     * @return ?string
     */
    public static function mfaChallenge(?string $challengeId): ?string
    {
        return self::id(self::MFA, $challengeId);
    }

    /**
     * A challenge of `laravel-authentication`'s own, by its id.
     *
     * @param  ?string  $challengeId
     * @return ?string
     */
    public static function authenticationChallenge(?string $challengeId): ?string
    {
        return self::id(self::AUTHENTICATION, $challengeId);
    }

    /**
     * A session's events, by the session's id.
     *
     * @param  ?string  $sessionId
     * @return ?string
     */
    public static function session(?string $sessionId): ?string
    {
        return self::id(self::SESSION, $sessionId);
    }

    /**
     * Every event of one `laravel-authorization` management call, by its
     * operation's id.
     *
     * @param  ?string  $operationId
     * @return ?string
     */
    public static function authorizationOperation(?string $operationId): ?string
    {
        return self::id(self::AUTHORIZATION, $operationId);
    }

    /**
     * The first of the candidates that is an id, or `null` when none is.
     *
     * @param  ?string  ...$candidates
     * @return ?string
     */
    public static function first(?string ...$candidates): ?string
    {
        foreach ($candidates as $candidate) {
            if ($candidate !== null) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * The namespace and parts joined by colons, or `null` when a part is
     * missing or empty or audit-log would refuse the id.
     *
     * @param  string  $namespace
     * @param  ?string  ...$parts
     * @return ?string
     */
    private static function id(string $namespace, ?string ...$parts): ?string
    {
        foreach ($parts as $part) {
            if ($part === null || $part === '') {
                return null;
            }
        }

        $id = $namespace . ':' . implode(':', $parts);

        return CorrelationId::isValid($id) ? $id : null;
    }
}
