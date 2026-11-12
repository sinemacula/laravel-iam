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
 * Records `laravel-authentication`'s events from each event alone, under
 * audit-log's own code where it means the same and a package code otherwise.
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
     * The code the event is recorded under, or `null` to skip it.
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
     * The code of a revocation: a user's own sign-out is audit-log's.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\SessionRevoked  $event
     * @return \BackedEnum
     */
    private static function revocationCode(SessionRevoked $event): \BackedEnum
    {
        return $event->reason === RevocationReason::SIGNED_OUT ? CapturedActivity::SIGNED_OUT : SessionActivity::REVOKED;
    }

    /**
     * The code of a verification: an email address's is audit-log's.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\IdentifierVerified  $event
     * @return \BackedEnum
     */
    private static function verificationCode(IdentifierVerified $event): \BackedEnum
    {
        return $event->type === self::EMAIL ? CapturedActivity::EMAIL_VERIFIED : AuthenticationActivity::IDENTIFIER_VERIFIED;
    }

    /**
     * The code of a refusal, by its flow.
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
     * Whether the refusal is a sign-in lockout; an account's own limit is
     * concealed, and `locked_out` would drop that flag.
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
     * Who a return to pending's record says acted: the identity for its own
     * switch or refresh, else the caller.
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
     * Who a revocation's record says acted.
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
     * The method and event details, less any null.
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
     * The principal a caller's event acted on, as properties, since the
     * record's principal is the caller's.
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
     * What a switch or a return to pending adds.
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
     * What a credential's or an external result's event adds.
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
     * The principal and tenant a session left when it switched.
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
     * A principal as properties under the prefix, its type mapped.
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
     * The challenge's correlation: MFA's for a factor code, else this member's.
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
     * Mark the refusal denied for a lockout, else failed, with the identifier.
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
