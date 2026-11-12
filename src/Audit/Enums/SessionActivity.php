<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Enums;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\Iam\Audit\Contracts\ListsProperties;

/**
 * The `session.*` codes `laravel-authentication`'s session events are recorded
 * under; a user's own sign-out is audit-log's `authentication.signed_out`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
enum SessionActivity: string implements ListsProperties
{
    // A session was written for a sign-in, or a pending one first activated
    case CREATED = 'session.created';

    // A sign-in's session was written pending a further factor or a choice
    case PENDING = 'session.pending';

    // A session that returned to pending was activated again
    case ACTIVATED = 'session.activated';

    // An active session returned to pending
    case RETURNED_TO_PENDING = 'session.returned_to_pending';

    // A session was revoked, for any reason but its user's own sign-out
    case REVOKED = 'session.revoked';

    // An identity's or a principal's sessions were ended together
    case SIGNED_OUT_EVERYWHERE = 'session.signed_out_everywhere';

    // A session's refresh token was exchanged
    case REFRESHED = 'session.refreshed';

    // A session switched the principal it acts as, its active tenant, or both
    case SWITCHED = 'session.switched';

    // A session was stepped up with a further factor
    case STEPPED_UP = 'session.stepped_up';

    // A session was reauthenticated
    case REAUTHENTICATED = 'session.reauthenticated';

    // A refresh-token exchange was refused
    case REFRESH_FAILED = 'session.refresh_failed';

    // A switch of principal or tenant was refused
    case SWITCH_FAILED = 'session.switch_failed';

    // A sign-out by refresh credential was refused
    case SIGN_OUT_FAILED = 'session.sign_out_failed';

    // A step-up was refused
    case STEP_UP_FAILED = 'session.step_up_failed';

    // A reauthentication was refused
    case REAUTHENTICATION_FAILED = 'session.reauthentication_failed';

    // A session failed its recheck after a factor was removed or changed
    case FACTOR_RECHECK_FAILED = 'session.factor_recheck_failed';

    /** @var string The category every session code is stored under. */
    private const string CATEGORY = 'security';

    /** @var list<string> What every refusal keeps. */
    private const array REFUSAL = ['method', 'retry_after', 'concealed'];

    /** @var list<string> What a change of principal or tenant keeps of what the session left. */
    private const array PREVIOUS = ['previous_principal_type', 'previous_principal_id', 'previous_tenant_id'];

    /** @var list<string> What a session's event left to the caller keeps of the principal the session acts as. */
    private const array SESSION = ['session_principal_type', 'session_principal_id'];

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
        return EventDefinition::for($this)->category(self::CATEGORY)->retain(...$this->retained());
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
     * The properties this case's code keeps.
     *
     * @return list<string>
     */
    private function retained(): array
    {
        return match ($this) {
            self::CREATED,
            self::ACTIVATED,
            self::REFRESHED,
            self::REAUTHENTICATED       => ['method'],
            self::PENDING               => ['method', 'requires', 'expires_at'],
            self::RETURNED_TO_PENDING   => ['method', 'flow', 'requires', 'expires_at', ...self::PREVIOUS, ...self::SESSION],
            self::REVOKED               => ['method', 'reason', ...self::SESSION],
            self::SIGNED_OUT_EVERYWHERE => ['reason', 'revoked', 'tokens_valid_after', 'scope_principal_type', 'scope_principal_id'],
            self::SWITCHED              => [...self::PREVIOUS, 'principal_changed', 'tenant_changed'],
            self::STEPPED_UP            => ['method', 'kind'],
            default                     => self::REFUSAL,
        };
    }
}
