<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Enums;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\Iam\Audit\Contracts\ListsProperties;

/**
 * The `sso.*` codes SSO's events are recorded under; administration is
 * `access_management`, so it can be kept longer than the flows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
enum SsoActivity: string implements ListsProperties
{
    // A flow was started
    case AUTHORIZATION_REQUEST_STARTED = 'sso.authorization_request_started';

    // A provider's response was verified
    case RESULT_VERIFIED = 'sso.result_verified';

    // A verified sign-in resolved to no identity
    case RESULT_UNLINKED            = 'sso.result_unlinked';
    case HANDOFF_ISSUED             = 'sso.handoff_issued';
    case HANDOFF_REDEEMED           = 'sso.handoff_redeemed';
    case REAUTHENTICATION_COMPLETED = 'sso.reauthentication_completed';

    // A flow's start, response, callback or redemption was refused
    case FLOW_FAILED = 'sso.flow_failed';

    // An unsolicited response was answered by starting a flow afresh
    case UNSOLICITED_RESPONSE_REINITIATED = 'sso.unsolicited_response_reinitiated';
    case LINK_CREATED                     = 'sso.link_created';
    case LINK_REMOVED                     = 'sso.link_removed';
    case LINK_ACTIVATED                   = 'sso.link_activated';
    case LINK_CONFIRMED                   = 'sso.link_confirmed';
    case LINK_SUSPENDED                   = 'sso.link_suspended';
    case CONNECTION_CREATED               = 'sso.connection_created';
    case CONNECTION_UPDATED               = 'sso.connection_updated';
    case CONNECTION_ENABLED               = 'sso.connection_enabled';
    case CONNECTION_DISABLED              = 'sso.connection_disabled';
    case CONNECTION_DELETED               = 'sso.connection_deleted';
    case DOMAIN_CLAIMED                   = 'sso.domain_claimed';
    case DOMAIN_VERIFIED                  = 'sso.domain_verified';
    case DOMAIN_RECHECK_FAILED            = 'sso.domain_recheck_failed';

    // A domain whose recheck failed passed it again
    case DOMAIN_RESTORED     = 'sso.domain_restored';
    case DOMAIN_LAPSED       = 'sso.domain_lapsed';
    case DOMAIN_REMOVED      = 'sso.domain_removed';
    case ENFORCEMENT_CHANGED = 'sso.enforcement_changed';

    // A session was established under an enforcement exemption
    case EXEMPTION_USED = 'sso.exemption_used';

    // A key or certificate was added
    case KEY_ADDED        = 'sso.key_added';
    case KEY_MADE_CURRENT = 'sso.key_made_current';

    // A key or certificate was retired
    case KEY_RETIRED = 'sso.key_retired';

    // A key or certificate is nearing the end of its validity
    case KEY_NEARING_EXPIRY      = 'sso.key_nearing_expiry';
    case METADATA_REFRESHED      = 'sso.metadata_refreshed';
    case METADATA_REFRESH_FAILED = 'sso.metadata_refresh_failed';
    case JWKS_REFRESHED          = 'sso.jwks_refreshed';
    case JWKS_REFRESH_FAILED     = 'sso.jwks_refresh_failed';

    /** @var string The category of the flows, links, exemptions, expiry warnings and refreshes. */
    private const string SECURITY = 'security';

    /** @var string The category of the administration of connections, domains, enforcement and keys. */
    private const string ACCESS_MANAGEMENT = 'access_management';

    /** @var list<string> What every code keeps of the connection. */
    private const array CONNECTION = ['connection_id', 'connection_tenant_id', 'protocol'];

    /** @var list<string> What a flow's code keeps. */
    private const array FLOW = [...self::CONNECTION, 'application', 'purpose', 'method'];

    /** @var list<string> What a key's code keeps of it. */
    private const array KEY = [...self::CONNECTION, 'key_id', 'use', 'fingerprint'];

    /** @var list<string> What a domain's code keeps of it. */
    private const array DOMAIN = [...self::CONNECTION, 'domain_id', 'domain'];

    /** @var array<string, list<string>> What each code keeps, by code; a code not listed is a flow's and keeps what a flow's keeps. */
    private const array RETAINED = [
        self::FLOW_FAILED->value             => [...self::FLOW, 'flow'],
        self::LINK_CREATED->value            => [...self::FLOW, 'origin'],
        self::LINK_ACTIVATED->value          => [...self::FLOW, 'link_id'],
        self::CONNECTION_CREATED->value      => self::CONNECTION,
        self::CONNECTION_UPDATED->value      => [...self::CONNECTION, 'changed_settings'],
        self::CONNECTION_ENABLED->value      => self::CONNECTION,
        self::CONNECTION_DISABLED->value     => self::CONNECTION,
        self::CONNECTION_DELETED->value      => self::CONNECTION,
        self::DOMAIN_CLAIMED->value          => [...self::DOMAIN, 'record_name', 'pending_expires_at'],
        self::DOMAIN_VERIFIED->value         => [...self::DOMAIN, 'verified_at'],
        self::DOMAIN_RECHECK_FAILED->value   => [...self::DOMAIN, 'lapses_at'],
        self::DOMAIN_RESTORED->value         => [...self::DOMAIN, 'verified_at', 'checked_at'],
        self::DOMAIN_LAPSED->value           => self::DOMAIN,
        self::DOMAIN_REMOVED->value          => [...self::DOMAIN, 'state'],
        self::ENFORCEMENT_CHANGED->value     => ['connection_tenant_id', 'enabled', 'connection_ids', 'version', 'previous_version'],
        self::EXEMPTION_USED->value          => ['connection_tenant_id', 'application', 'method', 'enforcement_version'],
        self::KEY_ADDED->value               => [...self::KEY, 'state', 'not_after'],
        self::KEY_MADE_CURRENT->value        => [...self::KEY, 'previous_key_id'],
        self::KEY_RETIRED->value             => self::KEY,
        self::KEY_NEARING_EXPIRY->value      => [...self::KEY, 'not_after', 'threshold_days'],
        self::METADATA_REFRESHED->value      => [...self::CONNECTION, 'changed_settings', 'metadata_version', 'trust_changed'],
        self::METADATA_REFRESH_FAILED->value => [...self::CONNECTION, 'failures', 'next_attempt_at'],
        self::JWKS_REFRESHED->value          => [...self::CONNECTION, 'jwks_version', 'keys_added', 'keys_removed', 'trust_changed'],
        self::JWKS_REFRESH_FAILED->value     => [...self::CONNECTION, 'next_refetch_at'],
    ];

    /**
     * This case's definition, dropping every property it does not list.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        return EventDefinition::for($this)->category($this->category())->retain(...$this->retained());
    }

    /**
     * Every property this case's code keeps.
     *
     * @return list<string>
     */
    #[\Override]
    public function properties(): array
    {
        return $this->retained();
    }

    /**
     * The category this case's code is stored under.
     *
     * @return string
     */
    private function category(): string
    {
        return match ($this) {
            self::CONNECTION_CREATED,
            self::CONNECTION_UPDATED,
            self::CONNECTION_ENABLED,
            self::CONNECTION_DISABLED,
            self::CONNECTION_DELETED,
            self::DOMAIN_CLAIMED,
            self::DOMAIN_VERIFIED,
            self::DOMAIN_RECHECK_FAILED,
            self::DOMAIN_RESTORED,
            self::DOMAIN_LAPSED,
            self::DOMAIN_REMOVED,
            self::ENFORCEMENT_CHANGED,
            self::KEY_ADDED,
            self::KEY_MADE_CURRENT,
            self::KEY_RETIRED => self::ACCESS_MANAGEMENT,
            default           => self::SECURITY,
        };
    }

    /**
     * The properties this case's code keeps.
     *
     * @return list<string>
     */
    private function retained(): array
    {
        return self::RETAINED[$this->value] ?? self::FLOW;
    }
}
