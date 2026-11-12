<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Audit\Enums\AuthenticationActivity;

/**
 * Unit tests for the `authentication.*` codes and their definitions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationActivity::class)]
final class AuthenticationActivityTest extends CodesTestCase
{
    /**
     * The enum under test.
     *
     * @return class-string<\SineMacula\Laravel\Iam\Audit\Enums\AuthenticationActivity>
     */
    #[\Override]
    protected static function enum(): string
    {
        return AuthenticationActivity::class;
    }

    /**
     * The reserved prefix its codes are under.
     *
     * @return list<string>
     */
    #[\Override]
    protected static function prefixes(): array
    {
        return ['authentication.'];
    }

    /**
     * Each code, with its category and what it keeps.
     *
     * @return array<string, array{0: string, 1: array<string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling>}>
     */
    #[\Override]
    protected static function expected(): array
    {
        $refusal = self::retained('method', 'retry_after', 'concealed');
        $key     = ['scopes', 'key_id', 'key_principal_type', 'key_principal_id'];

        return [
            'authentication.sign_in_failed_concealed'       => ['security', $refusal],
            'authentication.request_rejected'               => ['security', $refusal],
            'authentication.api_key_rejected'               => ['security', $refusal],
            'authentication.client_credentials_failed'      => ['security', $refusal],
            'authentication.code_request_failed'            => ['security', $refusal],
            'authentication.identifier_verification_failed' => ['security', $refusal],
            'authentication.password_reset_failed'          => ['security', $refusal],
            'authentication.identifier_change_failed'       => ['security', $refusal],
            'authentication.factor_code_failed'             => ['security', $refusal],
            'authentication.password_change_failed'         => ['security', $refusal],
            'authentication.external_result_redeemed'       => ['security', self::retained('flow', 'method', 'connection_id')],
            'authentication.external_result_unlinked'       => ['security', self::retained('method', 'connection_id', 'issuer')],
            'authentication.identifier_change_requested'    => ['security', [...self::retained('type', 'expires_at'), ...self::pseudonymised('identifier')]],
            'authentication.identifier_changed'             => ['security', [...self::retained('type'), ...self::pseudonymised('previous', 'identifier')]],
            'authentication.identifier_verified'            => ['security', self::retained('type')],
            'authentication.password_set'                   => ['security', self::retained('method')],
            'authentication.password_changed'               => ['security', self::retained('method')],
            'authentication.password_established'           => ['security', self::retained('method')],
            'authentication.passkey_added'                  => ['security', self::retained('method', 'passkey_id')],
            'authentication.passkey_removed'                => ['security', self::retained('method', 'passkey_id')],
            'authentication.passkey_used'                   => ['security', self::retained('method')],
            'authentication.api_key_issued'                 => ['security', self::retained(...$key)],
            'authentication.api_key_revoked'                => ['security', self::retained(...$key)],
            'authentication.api_key_rotated'                => ['security', self::retained(...[...$key, 'previous_key_id'])],
            'authentication.client_credentials_granted'     => ['security', self::retained('scopes')],
        ];
    }
}
