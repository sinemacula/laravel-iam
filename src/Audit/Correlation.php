<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

/**
 * The correlation ids the mappers tie the members' records together with
 * (IAM-9.5), one namespace per source, so ids from two members never collide:
 * one SSO sign-in as `sso:{connection_id}:{request_reference}`, across SSO's
 * completion and redemption and `laravel-authentication`'s redemption of its
 * result; an MFA challenge as `mfa:{challenge}`, across MFA's code and
 * verification events and `laravel-authentication`'s refused factor code; a
 * challenge of `laravel-authentication`'s own (a sign-in code, a passkey
 * ceremony, an identifier change) as `authentication:{challenge}`; a session's
 * events as `session:{session_id}`; and every event of one
 * `laravel-authorization` management call as `authorization:{operation_id}`.
 *
 * A part that is `null` or empty means no id at all, never a partial one: an
 * administration event, a failure before a request was matched, an event with
 * no session. An id is at most 191 bytes (`MAX_BYTES`), stricter than
 * audit-log's 191 characters, with a value that starts with no space and holds
 * no control character, bidirectional control or malformed UTF-8, as
 * audit-log's `correlatedWith()` requires; an id that would break any of these
 * is no id, so a mapper skips correlation rather than lose the whole record to
 * audit-log's refusal. A record holds one id: `first()` keeps the first of the
 * candidates that is one, in the order the mappers give them (an SSO sign-in,
 * then a challenge, then the session).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Correlation
{
    /** @var int The longest id, in bytes: audit-log's correlation column, counted in bytes. */
    public const int MAX_BYTES = 191;

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

    /** @var string The shape audit-log requires of an id: a lower-case namespace, a colon, and a value starting with a non-space. */
    private const string PATTERN = '/\A[a-z][a-z0-9_-]{0,31}:\S.*\z/u';

    /** @var string Every character audit-log would strip from an id: controls and bidirectional embeddings, overrides and isolates. */
    private const string UNCLEAN = '/[\p{Cc}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u';

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
     * The id of the namespace and parts, joined by colons, or `null` when a
     * part is missing or empty, or the id would not fit audit-log's column or
     * shape.
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

        return self::isValid($id) ? $id : null;
    }

    /**
     * Whether audit-log would take the id as it is: within the column, of the
     * namespaced shape, and already clean text.
     *
     * @param  string  $id
     * @return bool
     */
    private static function isValid(string $id): bool
    {
        return strlen($id) <= self::MAX_BYTES
            && preg_match(self::PATTERN, $id) === 1
            && preg_match(self::UNCLEAN, $id) === 0;
    }
}
