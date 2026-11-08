<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Mappers;

use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\Iam\Audit\Correlation;
use SineMacula\Laravel\Iam\Audit\Enums\SsoActivity;
use SineMacula\Laravel\Iam\Audit\Mappers\Enums\Attribution;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\ConnectionEnabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\DomainClaimed;
use SineMacula\Laravel\Sso\Events\DomainLapsed;
use SineMacula\Laravel\Sso\Events\DomainRecheckFailed;
use SineMacula\Laravel\Sso\Events\DomainRemoved;
use SineMacula\Laravel\Sso\Events\DomainRestored;
use SineMacula\Laravel\Sso\Events\DomainVerified;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\JwksRefreshed;
use SineMacula\Laravel\Sso\Events\JwksRefreshFailed;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyMadeCurrent;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Events\LinkActivated;
use SineMacula\Laravel\Sso\Events\LinkConfirmed;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Events\MetadataRefreshed;
use SineMacula\Laravel\Sso\Events\MetadataRefreshFailed;
use SineMacula\Laravel\Sso\Events\ReauthenticationCompleted;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Events\UnsolicitedResponseReinitiated;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * Records SSO's events (`SsoEvent`) in audit-log, from each event alone
 * (IAM-9.1, IAM-9.4), each under its own `SsoActivity` code.
 *
 * A flow's refusal (`FlowFailed`), a failed refresh and a failed domain recheck
 * carry their reason as the record's; SSO conceals none from the client. The
 * record's actor is the acting identity the application passed to an
 * administration helper, else the identity for its own flow or link, explicitly
 * no one for a refusal and for what SSO did by itself (a key nearing expiry, a
 * recheck, a lapse, a failed or JWKS refresh, a link suspended by a scope's
 * widening), and the caller for an administration helper called with no acting
 * identity, a link made by a connection's subject migration among them, which
 * the identity relinked never asked for. Its subject is the identity of a flow,
 * a link or an exemption, the connection of a connection's, a key's or a
 * refresh's event, and the domain of a domain's, each by SSO's own model's type
 * through the morph map; an enforcement change has none but its tenant. Its
 * tenant is the active tenant, else the connection's. The SSO application
 * stands for the guard, which is the same name in this package.
 *
 * One sign-in is correlated as `sso:{connection_id}:{request_reference}` across
 * its start, its verified result, its handoff and its redemption, which
 * `laravel-authentication`'s `ExternalResultRedeemed` correlates the same way,
 * so each half is recorded once; an event with no request, an administration
 * event among them, is correlated by its session, or not at all. An unlinked
 * result's provisioning grant is never recorded.
 *
 * It reads nothing but the event and the morph map, and keeps nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoEventMapper implements EventMapper
{
    /** @var array<class-string<\SineMacula\Laravel\Sso\Contracts\SsoEvent>, \SineMacula\Laravel\Iam\Audit\Enums\SsoActivity> The code of each of SSO's events. */
    private const array CODES = [
        AuthorizationRequestStarted::class    => SsoActivity::AUTHORIZATION_REQUEST_STARTED,
        ResultVerified::class                 => SsoActivity::RESULT_VERIFIED,
        ResultUnlinked::class                 => SsoActivity::RESULT_UNLINKED,
        HandoffIssued::class                  => SsoActivity::HANDOFF_ISSUED,
        HandoffRedeemed::class                => SsoActivity::HANDOFF_REDEEMED,
        ReauthenticationCompleted::class      => SsoActivity::REAUTHENTICATION_COMPLETED,
        FlowFailed::class                     => SsoActivity::FLOW_FAILED,
        UnsolicitedResponseReinitiated::class => SsoActivity::UNSOLICITED_RESPONSE_REINITIATED,
        LinkCreated::class                    => SsoActivity::LINK_CREATED,
        LinkRemoved::class                    => SsoActivity::LINK_REMOVED,
        LinkActivated::class                  => SsoActivity::LINK_ACTIVATED,
        LinkConfirmed::class                  => SsoActivity::LINK_CONFIRMED,
        LinkSuspended::class                  => SsoActivity::LINK_SUSPENDED,
        ConnectionCreated::class              => SsoActivity::CONNECTION_CREATED,
        ConnectionUpdated::class              => SsoActivity::CONNECTION_UPDATED,
        ConnectionEnabled::class              => SsoActivity::CONNECTION_ENABLED,
        ConnectionDisabled::class             => SsoActivity::CONNECTION_DISABLED,
        ConnectionDeleted::class              => SsoActivity::CONNECTION_DELETED,
        DomainClaimed::class                  => SsoActivity::DOMAIN_CLAIMED,
        DomainVerified::class                 => SsoActivity::DOMAIN_VERIFIED,
        DomainRecheckFailed::class            => SsoActivity::DOMAIN_RECHECK_FAILED,
        DomainRestored::class                 => SsoActivity::DOMAIN_RESTORED,
        DomainLapsed::class                   => SsoActivity::DOMAIN_LAPSED,
        DomainRemoved::class                  => SsoActivity::DOMAIN_REMOVED,
        EnforcementChanged::class             => SsoActivity::ENFORCEMENT_CHANGED,
        ExemptionUsed::class                  => SsoActivity::EXEMPTION_USED,
        KeyAdded::class                       => SsoActivity::KEY_ADDED,
        KeyMadeCurrent::class                 => SsoActivity::KEY_MADE_CURRENT,
        KeyRetired::class                     => SsoActivity::KEY_RETIRED,
        KeyNearingExpiry::class               => SsoActivity::KEY_NEARING_EXPIRY,
        MetadataRefreshed::class              => SsoActivity::METADATA_REFRESHED,
        MetadataRefreshFailed::class          => SsoActivity::METADATA_REFRESH_FAILED,
        JwksRefreshed::class                  => SsoActivity::JWKS_REFRESHED,
        JwksRefreshFailed::class              => SsoActivity::JWKS_REFRESH_FAILED,
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
        $code = $event instanceof SsoEvent ? self::code($event) : null;

        if ($code === null) {
            return null;
        }

        $context  = $event->context();
        $snapshot = Snapshot::ofSso($context);

        Snapshot::describe($record, $code, self::properties($event));

        $correlation = Correlation::first(Correlation::ssoSignIn($context->connectionId, $context->requestReference), Correlation::session($context->sessionId));

        if ($correlation !== null) {
            $record->correlatedWith($correlation);
        }

        $reason = self::reason($event);

        if ($reason !== null) {
            $record->failed($reason);
        }

        $operator = References::of($context->actingIdentityMorphClass, $context->actingIdentityId);

        return $snapshot->attribute($record, self::attribution($event), self::subject($event, $snapshot), $operator);
    }

    /**
     * The code the event is recorded under, or `null` for an event that is not
     * one of SSO's own.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return ?\SineMacula\Laravel\Iam\Audit\Enums\SsoActivity
     */
    private static function code(SsoEvent $event): ?SsoActivity
    {
        return self::CODES[$event::class] ?? null;
    }

    /**
     * Who the record says acted when the application passed no acting identity.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return \SineMacula\Laravel\Iam\Audit\Mappers\Enums\Attribution
     */
    private static function attribution(SsoEvent $event): Attribution
    {
        return match (true) {
            $event instanceof FlowFailed,
            $event instanceof LinkSuspended,
            $event instanceof DomainRecheckFailed,
            $event instanceof DomainRestored,
            $event instanceof DomainLapsed,
            $event instanceof KeyNearingExpiry,
            $event instanceof MetadataRefreshFailed,
            $event instanceof JwksRefreshed,
            $event instanceof JwksRefreshFailed => Attribution::NOBODY,
            $event instanceof LinkRemoved,
            $event instanceof ConnectionCreated,
            $event instanceof ConnectionUpdated,
            $event instanceof ConnectionEnabled,
            $event instanceof ConnectionDisabled,
            $event instanceof ConnectionDeleted,
            $event instanceof DomainClaimed,
            $event instanceof DomainVerified,
            $event instanceof DomainRemoved,
            $event instanceof EnforcementChanged,
            $event instanceof KeyAdded,
            $event instanceof KeyMadeCurrent,
            $event instanceof KeyRetired,
            $event instanceof MetadataRefreshed => Attribution::CALLER,
            $event instanceof LinkCreated       => $event->origin === LinkOrigin::MIGRATION ? Attribution::CALLER : Attribution::SUBJECT,
            default                             => Attribution::SUBJECT,
        };
    }

    /**
     * What the activity was done to: the domain, the connection, nothing for an
     * enforcement change, or the identity.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  \SineMacula\Laravel\Iam\Audit\Mappers\Snapshot  $snapshot
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function subject(SsoEvent $event, Snapshot $snapshot): ?Reference
    {
        $connection = References::of(Connection::class, $event->context()->connectionId);

        return match (true) {
            $event instanceof DomainClaimed,
            $event instanceof DomainVerified,
            $event instanceof DomainRecheckFailed,
            $event instanceof DomainRestored,
            $event instanceof DomainLapsed,
            $event instanceof DomainRemoved      => References::of(Domain::class, $event->domainId),
            $event instanceof EnforcementChanged => null,
            $event instanceof ConnectionCreated,
            $event instanceof ConnectionUpdated,
            $event instanceof ConnectionEnabled,
            $event instanceof ConnectionDisabled,
            $event instanceof ConnectionDeleted,
            $event instanceof KeyAdded,
            $event instanceof KeyMadeCurrent,
            $event instanceof KeyRetired,
            $event instanceof KeyNearingExpiry,
            $event instanceof MetadataRefreshed,
            $event instanceof MetadataRefreshFailed,
            $event instanceof JwksRefreshed,
            $event instanceof JwksRefreshFailed => $connection,
            default                             => $snapshot->identity,
        };
    }

    /**
     * The reason the event's operation failed, if it failed.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return ?\BackedEnum
     */
    private static function reason(SsoEvent $event): ?\BackedEnum
    {
        return match (true) {
            $event instanceof FlowFailed,
            $event instanceof MetadataRefreshFailed,
            $event instanceof JwksRefreshFailed   => $event->reason,
            $event instanceof DomainRecheckFailed => $event->failure,
            default                               => null,
        };
    }

    /**
     * The properties the event describes itself with: its connection, the
     * connection's tenant and protocol, the application, the purpose and the
     * method, and what the event adds; a value the event does not have is left
     * out. The code's definition decides which are kept.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return array<string, mixed>
     */
    private static function properties(SsoEvent $event): array
    {
        $context = $event->context();

        return array_filter([
            'connection_id'        => $context->connectionId,
            'connection_tenant_id' => $context->connectionTenantId,
            'protocol'             => $context->protocol,
            'application'          => $context->application,
            'purpose'              => $context->purpose,
            'method'               => $context->method,
            ...self::details($event),
        ], static fn (mixed $value): bool => $value !== null);
    }

    /**
     * What the event adds to its context.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return array<string, mixed>
     */
    private static function details(SsoEvent $event): array
    {
        return match (true) {
            $event instanceof FlowFailed         => ['flow' => $event->flow],
            $event instanceof LinkCreated        => ['origin' => $event->origin],
            $event instanceof LinkActivated      => ['link_id' => $event->linkId],
            $event instanceof ConnectionUpdated  => ['changed_settings' => $event->changedSettings],
            $event instanceof EnforcementChanged => [
                'enabled'          => $event->enabled,
                'connection_ids'   => $event->connectionIds,
                'version'          => $event->version,
                'previous_version' => $event->previousVersion,
            ],
            $event instanceof ExemptionUsed => ['enforcement_version' => $event->enforcementVersion],
            default                         => [...self::domainDetails($event), ...self::keyDetails($event), ...self::refreshDetails($event)],
        };
    }

    /**
     * What a domain's event adds: the domain, and what changed of it.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return array<string, mixed>
     */
    private static function domainDetails(SsoEvent $event): array
    {
        return match (true) {
            $event instanceof DomainClaimed => [
                ...self::domain($event->domainId, $event->domain),
                'record_name'        => $event->recordName,
                'pending_expires_at' => $event->pendingExpiresAt,
            ],
            $event instanceof DomainVerified      => [...self::domain($event->domainId, $event->domain), 'verified_at' => $event->verifiedAt],
            $event instanceof DomainRecheckFailed => [...self::domain($event->domainId, $event->domain), 'lapses_at' => $event->lapsesAt],
            $event instanceof DomainRestored      => [
                ...self::domain($event->domainId, $event->domain),
                'verified_at' => $event->verifiedAt,
                'checked_at'  => $event->checkedAt,
            ],
            $event instanceof DomainLapsed  => self::domain($event->domainId, $event->domain),
            $event instanceof DomainRemoved => [...self::domain($event->domainId, $event->domain), 'state' => $event->state],
            default                         => [],
        };
    }

    /**
     * A domain's id and name.
     *
     * @param  string  $id
     * @param  string  $domain
     * @return array{domain_id: string, domain: string}
     */
    private static function domain(string $id, string $domain): array
    {
        return ['domain_id' => $id, 'domain' => $domain];
    }

    /**
     * What a key's event adds: the key, and what changed of it.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return array<string, mixed>
     */
    private static function keyDetails(SsoEvent $event): array
    {
        return match (true) {
            $event instanceof KeyAdded => [
                ...self::key($event->keyId, $event->use, $event->fingerprint),
                'state'     => $event->state,
                'not_after' => $event->notAfter,
            ],
            $event instanceof KeyMadeCurrent   => [...self::key($event->keyId, $event->use, $event->fingerprint), 'previous_key_id' => $event->previousKeyId],
            $event instanceof KeyRetired       => self::key($event->keyId, $event->use, $event->fingerprint),
            $event instanceof KeyNearingExpiry => [
                ...self::key($event->keyId, $event->use, $event->fingerprint),
                'not_after'      => $event->notAfter,
                'threshold_days' => $event->thresholdDays,
            ],
            default => [],
        };
    }

    /**
     * A key's id, use and fingerprint.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  string  $fingerprint
     * @return array{key_id: string, use: \SineMacula\Laravel\Sso\Keys\Enums\KeyUse, fingerprint: string}
     */
    private static function key(string $id, KeyUse $use, string $fingerprint): array
    {
        return ['key_id' => $id, 'use' => $use, 'fingerprint' => $fingerprint];
    }

    /**
     * What a refresh of metadata or JWKS adds.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return array<string, mixed>
     */
    private static function refreshDetails(SsoEvent $event): array
    {
        return match (true) {
            $event instanceof MetadataRefreshed => [
                'changed_settings' => $event->changedSettings,
                'metadata_version' => $event->metadataVersion,
                'trust_changed'    => $event->trustChanged,
            ],
            $event instanceof MetadataRefreshFailed => ['failures' => $event->failures, 'next_attempt_at' => $event->nextAttemptAt],
            $event instanceof JwksRefreshed         => [
                'jwks_version'  => $event->jwksVersion,
                'keys_added'    => $event->keysAdded,
                'keys_removed'  => $event->keysRemoved,
                'trust_changed' => $event->trustChanged,
            ],
            $event instanceof JwksRefreshFailed => ['next_refetch_at' => $event->nextRefetchAt],
            default                             => [],
        };
    }
}
