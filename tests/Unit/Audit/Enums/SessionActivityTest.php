<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Audit\Enums\SessionActivity;

/**
 * Unit tests for the `session.*` codes and their definitions (IAM-9.2,
 * IAM-9.3): every code in the `security` category, keeping exactly its
 * properties, a refusal its method, wait and concealment.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionActivity::class)]
final class SessionActivityTest extends CodesTestCase
{
    /**
     * The enum under test.
     *
     * @return class-string<\SineMacula\Laravel\Iam\Audit\Enums\SessionActivity>
     */
    #[\Override]
    protected static function enum(): string
    {
        return SessionActivity::class;
    }

    /**
     * The reserved prefix its codes are under.
     *
     * @return list<string>
     */
    #[\Override]
    protected static function prefixes(): array
    {
        return ['session.'];
    }

    /**
     * Each code, with its category and what it keeps.
     *
     * @return array<string, array{0: string, 1: array<string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling>}>
     */
    #[\Override]
    protected static function expected(): array
    {
        $refusal  = self::retained('method', 'retry_after', 'concealed');
        $previous = ['previous_principal_type', 'previous_principal_id', 'previous_tenant_id'];
        $session  = ['session_principal_type', 'session_principal_id'];

        return [
            'session.created'                 => ['security', self::retained('method')],
            'session.pending'                 => ['security', self::retained('method', 'requires', 'expires_at')],
            'session.activated'               => ['security', self::retained('method')],
            'session.returned_to_pending'     => ['security', self::retained('method', 'flow', 'requires', 'expires_at', ...$previous, ...$session)],
            'session.revoked'                 => ['security', self::retained('method', 'reason', ...$session)],
            'session.signed_out_everywhere'   => ['security', self::retained('reason', 'revoked', 'tokens_valid_after', 'scope_principal_type', 'scope_principal_id')],
            'session.refreshed'               => ['security', self::retained('method')],
            'session.switched'                => ['security', self::retained(...$previous, ...['principal_changed', 'tenant_changed'])],
            'session.stepped_up'              => ['security', self::retained('method', 'kind')],
            'session.reauthenticated'         => ['security', self::retained('method')],
            'session.refresh_failed'          => ['security', $refusal],
            'session.switch_failed'           => ['security', $refusal],
            'session.sign_out_failed'         => ['security', $refusal],
            'session.step_up_failed'          => ['security', $refusal],
            'session.reauthentication_failed' => ['security', $refusal],
            'session.factor_recheck_failed'   => ['security', $refusal],
        ];
    }
}
