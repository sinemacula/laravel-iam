<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Mappers;

use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\ApiKeyIssued;
use SineMacula\Laravel\Authentication\Events\ApiKeyRevoked;
use SineMacula\Laravel\Authentication\Events\ApiKeyRotated;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\ClientCredentialsGranted;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\ExternalResultRedeemed;
use SineMacula\Laravel\Authentication\Events\ExternalResultUnlinked;
use SineMacula\Laravel\Authentication\Events\IdentifierChanged;
use SineMacula\Laravel\Authentication\Events\IdentifierChangeRequested;
use SineMacula\Laravel\Authentication\Events\IdentifierVerified;
use SineMacula\Laravel\Authentication\Events\PasskeyAdded;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Events\PasskeyUsed;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionActivated;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionPending;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Events\SteppedUp;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Iam\Audit\Correlation;
use SineMacula\Laravel\Iam\Audit\Enums\AuthenticationActivity;
use SineMacula\Laravel\Iam\Audit\Enums\SessionActivity;
use SineMacula\Laravel\Iam\Audit\Mappers\Enums\Attribution;
use SineMacula\Laravel\Iam\Audit\References;

/**
 * Records `laravel-authentication`'s events (`AuthenticationEvent`) in
 * audit-log, from each event alone (IAM-9.1, IAM-9.4).
 *
 * Each event is recorded under a code chosen by what happened, never by its
 * class: audit-log's own codes for an event that means the same
 * (`authentication.signed_in`, `sign_in_failed`, `locked_out`, `signed_out`,
 * `account.email_verified`, `account.password_reset`), and otherwise this
 * package's `AuthenticationActivity` and `SessionActivity` codes. A refusal
 * (`AuthenticationFailed`) is recorded by its flow: a sign-in's as
 * `authentication.sign_in_failed`, as `authentication.locked_out` when the
 * identifier, the session or the IP address has used up its attempts
 * (`rate_limited`), denied and about no one, as audit-log records Laravel's
 * `Lockout`, or as `sign_in_failed_concealed` when its reason is concealed from
 * the client (an account's own limit among them), a bearer token's as
 * `authentication.request_rejected`, a refresh's as `session.refresh_failed`,
 * and so on; its reason is the record's, marked `concealed` when
 * `laravel-authentication` hides it from the client, so it is never rendered,
 * and the identifier it names is hashed by audit-log, never kept. A session
 * event is a `session.*` code; a user's own sign-out is
 * `authentication.signed_out`. Laravel's `Login`, `Failed` and `Logout`, which
 * the guards dispatch beside these, are left to audit-log's own capture, from
 * which every `jwt` and `api_key` guard is excluded (IAM-9.6). A sign-in
 * through a guard's own `attempt()` or `login()` dispatches only Laravel's
 * `Login` and a bind's noise, never `SignedIn`, so on an excluded guard nothing
 * records it until `laravel-authentication` reports it with an event of its
 * own; its refusal is recorded as any other.
 *
 * The noise of a bind (`PrincipalAssigned`, `SessionAuthenticated`) is skipped,
 * and so is a refresh's `SignedIn`, which repeats the `Refreshed` recorded
 * beside it; a sign-in's `SessionCreated` and `SignedIn` are two facts and are
 * recorded once each, as are SSO's and this member's halves of one external
 * sign-in, which `ExternalResultRedeemed` correlates.
 *
 * The record's actor is the identity for its own action (a return to pending
 * its own switch or refresh made among them), explicitly no one for a refusal
 * (its author was never proven) and a detected replay, and the caller otherwise
 * (a revocation, a return to pending after a factor change, an API key's
 * management), which the contributors fill. Its subject is the identity, none
 * for a lockout, and its tenant, guard, session and client the event's, and its
 * principal too unless its actor is left to the caller. That principal is the
 * caller's, so the principal the event names, what the activity was done to, is
 * kept as properties (`scope_principal_*` for a bulk sign-out,
 * `key_principal_*` for an API key's management, `session_principal_*` for a
 * revocation or a return to pending), while its tenant stays the record's, the
 * boundary the activity happened in. The credential is the one the activity
 * used: a passkey added or removed, and an API key issued, revoked or rotated,
 * name the credential they manage instead, which is kept as a property
 * (`passkey_id`, `key_id`) and never as the record's credential. It is
 * correlated as one SSO sign-in when the event names its connection and
 * request, as a challenge when a refusal names one (`mfa:` for a further
 * factor's code, which MFA's events name too, `authentication:` for the
 * others), and otherwise by its session.
 *
 * A refusal is written once the transaction around it ends, so a rollback
 * cannot take it (IAM-9.5).
 *
 * Beyond that, it reads nothing but the event and the morph map, and keeps
 * nothing itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthenticationEventMapper implements EventMapper
{
    /** @var string The identifier type whose verification is audit-log's `account.email_verified`. */
    private const string EMAIL = 'email';

    /** @var array<class-string<\SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent>, \SineMacula\Laravel\Iam\Audit\Enums\SessionActivity> The code of each session event recorded by what it is alone. */
    private const array SESSIONS = [
        SessionCreated::class           => SessionActivity::CREATED,
        SessionPending::class           => SessionActivity::PENDING,
        SessionActivated::class         => SessionActivity::ACTIVATED,
        SessionReturnedToPending::class => SessionActivity::RETURNED_TO_PENDING,
        SignedOutEverywhere::class      => SessionActivity::SIGNED_OUT_EVERYWHERE,
        Refreshed::class                => SessionActivity::REFRESHED,
        PrincipalSwitched::class        => SessionActivity::SWITCHED,
        SteppedUp::class                => SessionActivity::STEPPED_UP,
        Reauthenticated::class          => SessionActivity::REAUTHENTICATED,
    ];

    /** @var array<class-string<\SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent>, \SineMacula\Laravel\Iam\Audit\Enums\AuthenticationActivity> The code of each other event recorded by what it is alone. */
    private const array CODES = [
        ExternalResultRedeemed::class    => AuthenticationActivity::EXTERNAL_RESULT_REDEEMED,
        ExternalResultUnlinked::class    => AuthenticationActivity::EXTERNAL_RESULT_UNLINKED,
        IdentifierChangeRequested::class => AuthenticationActivity::IDENTIFIER_CHANGE_REQUESTED,
        IdentifierChanged::class         => AuthenticationActivity::IDENTIFIER_CHANGED,
        PasskeyAdded::class              => AuthenticationActivity::PASSKEY_ADDED,
        PasskeyRemoved::class            => AuthenticationActivity::PASSKEY_REMOVED,
        PasskeyUsed::class               => AuthenticationActivity::PASSKEY_USED,
        ApiKeyIssued::class              => AuthenticationActivity::API_KEY_ISSUED,
        ApiKeyRevoked::class             => AuthenticationActivity::API_KEY_REVOKED,
        ApiKeyRotated::class             => AuthenticationActivity::API_KEY_ROTATED,
        ClientCredentialsGranted::class  => AuthenticationActivity::CLIENT_CREDENTIALS_GRANTED,
    ];

    /** @var array<class-string<\SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent>, \BackedEnum> The code of each event recorded by what it is alone, of either kind. */
    private const array EVENTS = [...self::SESSIONS, ...self::CODES];

    /** @var array<string, \BackedEnum> The code of a refusal, by its flow. */
    private const array REFUSALS = [
        AuthenticationFlow::SIGN_IN->value                 => CapturedActivity::SIGN_IN_FAILED,
        AuthenticationFlow::BEARER->value                  => AuthenticationActivity::REQUEST_REJECTED,
        AuthenticationFlow::REFRESH->value                 => SessionActivity::REFRESH_FAILED,
        AuthenticationFlow::SWITCH->value                  => SessionActivity::SWITCH_FAILED,
        AuthenticationFlow::SIGN_OUT->value                => SessionActivity::SIGN_OUT_FAILED,
        AuthenticationFlow::CODE_REQUEST->value            => AuthenticationActivity::CODE_REQUEST_FAILED,
        AuthenticationFlow::IDENTIFIER_VERIFICATION->value => AuthenticationActivity::IDENTIFIER_VERIFICATION_FAILED,
        AuthenticationFlow::API_KEY->value                 => AuthenticationActivity::API_KEY_REJECTED,
        AuthenticationFlow::CLIENT_CREDENTIALS->value      => AuthenticationActivity::CLIENT_CREDENTIALS_FAILED,
        AuthenticationFlow::PASSWORD_RESET->value          => AuthenticationActivity::PASSWORD_RESET_FAILED,
        AuthenticationFlow::IDENTIFIER_CHANGE->value       => AuthenticationActivity::IDENTIFIER_CHANGE_FAILED,
        AuthenticationFlow::STEP_UP->value                 => SessionActivity::STEP_UP_FAILED,
        AuthenticationFlow::REAUTHENTICATION->value        => SessionActivity::REAUTHENTICATION_FAILED,
        AuthenticationFlow::FACTOR_CODE->value             => AuthenticationActivity::FACTOR_CODE_FAILED,
        AuthenticationFlow::PASSWORD_CHANGE->value         => AuthenticationActivity::PASSWORD_CHANGE_FAILED,
        AuthenticationFlow::FACTOR_CHANGE->value           => SessionActivity::FACTOR_RECHECK_FAILED,
    ];

    /** @var list<class-string<\SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent>> The events naming the credential they manage, not one the activity used. */
    private const array MANAGED = [PasskeyAdded::class, PasskeyRemoved::class, ApiKeyIssued::class, ApiKeyRevoked::class, ApiKeyRotated::class];

    /** @var array<string, \BackedEnum> The code of a password set, by its flow: a reset is audit-log's own. */
    private const array PASSWORDS = [
        PasswordFlow::REGISTRATION->value  => AuthenticationActivity::PASSWORD_SET,
        PasswordFlow::CHANGE->value        => AuthenticationActivity::PASSWORD_CHANGED,
        PasswordFlow::RESET->value         => CapturedActivity::PASSWORD_RESET,
        PasswordFlow::ESTABLISHMENT->value => AuthenticationActivity::PASSWORD_ESTABLISHED,
    ];

    /**
     * Describe the event on the record, or skip it.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord
    {
        $code = $event instanceof AuthenticationEvent ? self::code($event) : null;

        if ($code === null) {
            return null;
        }

        $context     = $event->context();
        $snapshot    = Snapshot::ofAuthentication($context);
        $attribution = self::attribution($event);

        Snapshot::describe($record, $code, self::properties($event, $attribution));

        if ($context->credentialId !== null && $context->credentialId !== '' && !in_array($event::class, self::MANAGED, true)) {
            $record->usingCredential($context->credentialId);
        }

        $correlation = Correlation::first(
            Correlation::ssoSignIn($context->connectionId, $context->requestReference),
            $event instanceof AuthenticationFailed ? self::challenge($event) : null,
            Correlation::session($context->sessionId),
        );

        if ($correlation !== null) {
            $record->correlatedWith($correlation);
        }

        if ($event instanceof AuthenticationFailed) {
            self::refuse($record->afterTransaction(), $event);
        }

        $subject = $event instanceof AuthenticationFailed && self::isLockout($event) ? null : $snapshot->identity;

        return $snapshot->attribute($record, $attribution, $subject);
    }

    /**
     * The code the event is recorded under, or `null` to skip it: by its flow,
     * its reason or its type where those decide, and otherwise by the event
     * alone.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return ?\BackedEnum
     */
    private static function code(AuthenticationEvent $event): ?\BackedEnum
    {
        return match (true) {
            $event instanceof SignedIn             => $event->refresh ? null : CapturedActivity::SIGNED_IN,
            $event instanceof AuthenticationFailed => self::refusalCode($event),
            $event instanceof SessionRevoked       => self::revocationCode($event),
            $event instanceof IdentifierVerified   => self::verificationCode($event),
            $event instanceof PasswordSet          => self::PASSWORDS[$event->flow->value],
            default                                => self::EVENTS[$event::class] ?? null,
        };
    }

    /**
     * The code a revocation is recorded under: a user's own sign-out is
     * audit-log's own.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\SessionRevoked  $event
     * @return \BackedEnum
     */
    private static function revocationCode(SessionRevoked $event): \BackedEnum
    {
        return $event->reason === RevocationReason::SIGNED_OUT ? CapturedActivity::SIGNED_OUT : SessionActivity::REVOKED;
    }

    /**
     * The code an identifier's verification is recorded under: an email
     * address's is audit-log's own.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\IdentifierVerified  $event
     * @return \BackedEnum
     */
    private static function verificationCode(IdentifierVerified $event): \BackedEnum
    {
        return $event->type === self::EMAIL ? CapturedActivity::EMAIL_VERIFIED : AuthenticationActivity::IDENTIFIER_VERIFIED;
    }

    /**
     * The code a refusal is recorded under, by its flow: a sign-in's is
     * audit-log's own, its lockout's when its attempts are used up, unless its
     * reason is concealed.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\AuthenticationFailed  $event
     * @return \BackedEnum
     */
    private static function refusalCode(AuthenticationFailed $event): \BackedEnum
    {
        if (self::isLockout($event)) {
            return CapturedActivity::LOCKED_OUT;
        }

        if ($event->flow === AuthenticationFlow::SIGN_IN && $event->reason->isConcealed()) {
            return AuthenticationActivity::SIGN_IN_FAILED_CONCEALED;
        }

        return self::REFUSALS[$event->flow->value];
    }

    /**
     * Whether the refusal is a sign-in's lockout: the identifier, the session
     * or the IP address has used up its attempts, which audit-log's
     * `authentication.locked_out` means. An account's own limit
     * (`account_rate_limited`) is concealed, and so is no lockout here, whose
     * code would drop the `concealed` flag.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\AuthenticationFailed  $event
     * @return bool
     */
    private static function isLockout(AuthenticationFailed $event): bool
    {
        return $event->flow === AuthenticationFlow::SIGN_IN && $event->reason === FailureReason::RATE_LIMITED;
    }

    /**
     * Who the record says acted.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return \SineMacula\Laravel\Iam\Audit\Mappers\Enums\Attribution
     */
    private static function attribution(AuthenticationEvent $event): Attribution
    {
        return match (true) {
            $event instanceof AuthenticationFailed,
            $event instanceof ExternalResultUnlinked   => Attribution::NOBODY,
            $event instanceof SessionRevoked           => self::revocationAttribution($event->reason),
            $event instanceof SessionReturnedToPending => self::returnAttribution($event->flow),
            $event instanceof SignedOutEverywhere,
            $event instanceof PasskeyRemoved,
            $event instanceof ApiKeyIssued,
            $event instanceof ApiKeyRevoked,
            $event instanceof ApiKeyRotated => Attribution::CALLER,
            default                         => Attribution::SUBJECT,
        };
    }

    /**
     * Who a return to pending's record says acted: the identity for one its own
     * session's action made (its switch, or its refresh falling short of what
     * the session now requires), and the caller for any other (a factor change,
     * which the member does not say who made).
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @return \SineMacula\Laravel\Iam\Audit\Mappers\Enums\Attribution
     */
    private static function returnAttribution(AuthenticationFlow $flow): Attribution
    {
        return match ($flow) {
            AuthenticationFlow::SWITCH,
            AuthenticationFlow::REFRESH => Attribution::SUBJECT,
            default                     => Attribution::CALLER,
        };
    }

    /**
     * Who a revocation's record says acted: the identity for its own sign-out
     * and a session its own sign-in replaced, no one for a replay the package
     * detected, and the caller for any other.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @return \SineMacula\Laravel\Iam\Audit\Mappers\Enums\Attribution
     */
    private static function revocationAttribution(RevocationReason $reason): Attribution
    {
        return match ($reason) {
            RevocationReason::SIGNED_OUT,
            RevocationReason::SUPERSEDED     => Attribution::SUBJECT,
            RevocationReason::ROTATION_REUSE => Attribution::NOBODY,
            default                          => Attribution::CALLER,
        };
    }

    /**
     * The properties the event describes itself with, beside its context's
     * sign-in method, the credential it manages and, when its actor is left to
     * the caller, the principal it acted on; a value the event does not have is
     * left out. The code's definition decides which are kept.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @param  \SineMacula\Laravel\Iam\Audit\Mappers\Enums\Attribution  $attribution
     * @return array<string, mixed>
     */
    private static function properties(AuthenticationEvent $event, Attribution $attribution): array
    {
        $context    = $event->context();
        $properties = [
            'method' => $context->method,
            ...self::sessionProperties($event),
            ...self::identifierProperties($event),
            ...self::credentialProperties($event),
            ...($attribution === Attribution::CALLER ? self::actedOn($event) : []),
        ];

        return array_filter($properties, static fn (mixed $value): bool => $value !== null);
    }

    /**
     * What an event whose actor is left to the caller adds: the principal its
     * context names, which is what the activity was done to, not who the actor
     * acted as, kept as properties named for what it is (a bulk sign-out's
     * principal scope, an API key's principal, a revoked or returned session's
     * principal), since the record's principal is the actor's.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return array<string, ?string>
     */
    private static function actedOn(AuthenticationEvent $event): array
    {
        $prefix = match (true) {
            $event instanceof SignedOutEverywhere => 'scope',
            $event instanceof ApiKeyIssued,
            $event instanceof ApiKeyRevoked,
            $event instanceof ApiKeyRotated => 'key',
            $event instanceof SessionRevoked,
            $event instanceof SessionReturnedToPending => 'session',
            default                                    => null,
        };

        $context = $event->context();

        return $prefix === null ? [] : self::principal($prefix, $context->principalType, $context->principalId);
    }

    /**
     * What a session's event or a refusal adds.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return array<string, mixed>
     */
    private static function sessionProperties(AuthenticationEvent $event): array
    {
        return match (true) {
            $event instanceof AuthenticationFailed => ['retry_after' => $event->retryAfter, 'concealed' => $event->reason->isConcealed() ? true : null],
            $event instanceof SessionPending       => ['requires' => $event->requires, 'expires_at' => $event->expiresAt],
            $event instanceof SessionRevoked       => ['reason' => $event->reason],
            $event instanceof SignedOutEverywhere  => ['reason' => $event->reason, 'revoked' => $event->revoked, 'tokens_valid_after' => $event->tokensValidAfter],
            $event instanceof SteppedUp            => ['kind' => $event->kind],
            default                                => self::changeProperties($event),
        };
    }

    /**
     * What a change of a session's principal or tenant, or its return to
     * pending, adds.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return array<string, mixed>
     */
    private static function changeProperties(AuthenticationEvent $event): array
    {
        return match (true) {
            $event instanceof SessionReturnedToPending => [
                'flow'       => $event->flow,
                'requires'   => $event->requires,
                'expires_at' => $event->expiresAt,
                ...self::previous($event->previousPrincipalType, $event->previousPrincipalId, $event->previousTenantId),
            ],
            $event instanceof PrincipalSwitched => [
                ...self::previous($event->previousPrincipalType, $event->previousPrincipalId, $event->previousTenantId),
                'principal_changed' => $event->principalChanged,
                'tenant_changed'    => $event->tenantChanged,
            ],
            default => [],
        };
    }

    /**
     * What an identifier's event adds.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return array<string, mixed>
     */
    private static function identifierProperties(AuthenticationEvent $event): array
    {
        return match (true) {
            $event instanceof IdentifierChangeRequested => ['type' => $event->type, 'identifier' => $event->identifier, 'expires_at' => $event->expiresAt],
            $event instanceof IdentifierChanged         => ['type' => $event->type, 'previous' => $event->previous, 'identifier' => $event->identifier],
            $event instanceof IdentifierVerified        => ['type' => $event->type],
            default                                     => [],
        };
    }

    /**
     * What a credential's event, or an external result's, adds: a managed
     * credential's id among it, which is never the record's credential, since
     * the activity did not use it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent  $event
     * @return array<string, mixed>
     */
    private static function credentialProperties(AuthenticationEvent $event): array
    {
        $context = $event->context();
        $managed = $context->credentialId === '' ? null : $context->credentialId;

        return match (true) {
            $event instanceof ExternalResultRedeemed => ['flow' => $event->flow, 'connection_id' => $context->connectionId],
            $event instanceof ExternalResultUnlinked => ['connection_id' => $context->connectionId, 'issuer' => $event->issuer],
            $event instanceof PasskeyAdded,
            $event instanceof PasskeyRemoved => ['passkey_id' => $managed],
            $event instanceof ApiKeyRotated  => ['scopes' => $context->scopes, 'previous_key_id' => $event->previousKeyId, 'key_id' => $managed],
            $event instanceof ApiKeyIssued,
            $event instanceof ApiKeyRevoked            => ['scopes' => $context->scopes, 'key_id' => $managed],
            $event instanceof ClientCredentialsGranted => ['scopes' => $context->scopes],
            default                                    => [],
        };
    }

    /**
     * What a session left when it changed principal or tenant: the previous
     * principal and the previous tenant's id.
     *
     * @param  ?string  $type
     * @param  ?string  $id
     * @param  ?string  $tenantId
     * @return array<string, ?string>
     */
    private static function previous(?string $type, ?string $id, ?string $tenantId): array
    {
        return [...self::principal('previous', $type, $id), 'previous_tenant_id' => $tenantId];
    }

    /**
     * A principal kept as properties under the prefix: its type, read through
     * the morph map, and its id.
     *
     * @param  string  $prefix
     * @param  ?string  $type
     * @param  ?string  $id
     * @return array<string, ?string>
     */
    private static function principal(string $prefix, ?string $type, ?string $id): array
    {
        return [
            $prefix . '_principal_type' => $type === null ? null : References::type($type),
            $prefix . '_principal_id'   => $id,
        ];
    }

    /**
     * The correlation of the challenge a refusal names: MFA's namespace for a
     * further factor's code, whose challenge MFA's own events name, and
     * `laravel-authentication`'s for any other.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\AuthenticationFailed  $event
     * @return ?string
     */
    private static function challenge(AuthenticationFailed $event): ?string
    {
        return $event->flow === AuthenticationFlow::FACTOR_CODE
            ? Correlation::mfaChallenge($event->challengeId)
            : Correlation::authenticationChallenge($event->challengeId);
    }

    /**
     * Record the refusal: denied with its reason for a lockout, as audit-log's
     * own code is, failed with it otherwise, and the identifier it named, which
     * audit-log hashes.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @param  \SineMacula\Laravel\Authentication\Events\AuthenticationFailed  $event
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function refuse(PendingRecord $record, AuthenticationFailed $event): void
    {
        if ($event->identifier !== null && $event->identifier !== '') {
            $record->withIdentifier($event->identifier);
        }

        if (self::isLockout($event)) {
            $record->denied($event->reason);

            return;
        }

        $record->failed($event->reason);
    }
}
