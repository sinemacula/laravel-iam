<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Audit\Enums\SsoActivity;

/**
 * Unit tests for the `sso.*` codes and their definitions (IAM-9.2, IAM-9.3):
 * the flows, links, exemptions, expiry warnings and refreshes in the `security`
 * category, the administration of connections, domains, enforcement and keys in
 * `access_management`, each keeping exactly its properties.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoActivity::class)]
final class SsoActivityTest extends CodesTestCase
{
    /**
     * The enum under test.
     *
     * @return class-string<\SineMacula\Laravel\Iam\Audit\Enums\SsoActivity>
     */
    #[\Override]
    protected static function enum(): string
    {
        return SsoActivity::class;
    }

    /**
     * The reserved prefix its codes are under.
     *
     * @return list<string>
     */
    #[\Override]
    protected static function prefixes(): array
    {
        return ['sso.'];
    }

    /**
     * Each code, with its category and what it keeps.
     *
     * @return array<string, array{0: string, 1: array<string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling>}>
     */
    #[\Override]
    protected static function expected(): array
    {
        $connection = ['connection_id', 'connection_tenant_id', 'protocol'];
        $flow       = [...$connection, 'application', 'purpose', 'method'];
        $domain     = [...$connection, 'domain_id', 'domain'];
        $key        = [...$connection, 'key_id', 'use', 'fingerprint'];
        $managed    = 'access_management';

        return [
            'sso.authorization_request_started'    => ['security', self::retained(...$flow)],
            'sso.result_verified'                  => ['security', self::retained(...$flow)],
            'sso.result_unlinked'                  => ['security', self::retained(...$flow)],
            'sso.handoff_issued'                   => ['security', self::retained(...$flow)],
            'sso.handoff_redeemed'                 => ['security', self::retained(...$flow)],
            'sso.reauthentication_completed'       => ['security', self::retained(...$flow)],
            'sso.flow_failed'                      => ['security', self::retained(...$flow, ...['flow'])],
            'sso.unsolicited_response_reinitiated' => ['security', self::retained(...$flow)],
            'sso.link_created'                     => ['security', self::retained(...$flow, ...['origin'])],
            'sso.link_removed'                     => ['security', self::retained(...$flow)],
            'sso.link_activated'                   => ['security', self::retained(...$flow, ...['link_id'])],
            'sso.link_confirmed'                   => ['security', self::retained(...$flow)],
            'sso.link_suspended'                   => ['security', self::retained(...$flow)],
            'sso.connection_created'               => [$managed, self::retained(...$connection)],
            'sso.connection_updated'               => [$managed, self::retained(...$connection, ...['changed_settings'])],
            'sso.connection_enabled'               => [$managed, self::retained(...$connection)],
            'sso.connection_disabled'              => [$managed, self::retained(...$connection)],
            'sso.connection_deleted'               => [$managed, self::retained(...$connection)],
            'sso.domain_claimed'                   => [$managed, self::retained(...$domain, ...['record_name', 'pending_expires_at'])],
            'sso.domain_verified'                  => [$managed, self::retained(...$domain, ...['verified_at'])],
            'sso.domain_recheck_failed'            => [$managed, self::retained(...$domain, ...['lapses_at'])],
            'sso.domain_restored'                  => [$managed, self::retained(...$domain, ...['verified_at', 'checked_at'])],
            'sso.domain_lapsed'                    => [$managed, self::retained(...$domain)],
            'sso.domain_removed'                   => [$managed, self::retained(...$domain, ...['state'])],
            'sso.enforcement_changed'              => [$managed, self::retained('connection_tenant_id', 'enabled', 'connection_ids', 'version', 'previous_version')],
            'sso.exemption_used'                   => ['security', self::retained('connection_tenant_id', 'application', 'method', 'enforcement_version')],
            'sso.key_added'                        => [$managed, self::retained(...$key, ...['state', 'not_after'])],
            'sso.key_made_current'                 => [$managed, self::retained(...$key, ...['previous_key_id'])],
            'sso.key_retired'                      => [$managed, self::retained(...$key)],
            'sso.key_nearing_expiry'               => ['security', self::retained(...$key, ...['not_after', 'threshold_days'])],
            'sso.metadata_refreshed'               => ['security', self::retained(...$connection, ...['changed_settings', 'metadata_version', 'trust_changed'])],
            'sso.metadata_refresh_failed'          => ['security', self::retained(...$connection, ...['failures', 'next_attempt_at'])],
            'sso.jwks_refreshed'                   => ['security', self::retained(...$connection, ...['jwks_version', 'keys_added', 'keys_removed', 'trust_changed'])],
            'sso.jwks_refresh_failed'              => ['security', self::retained(...$connection, ...['next_refetch_at'])],
        ];
    }
}
