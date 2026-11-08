<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Fills what a record lacks from `laravel-authentication`'s caller, already
 * resolved (IAM-9.7): the actor, the guard, the principal, the tenant and the
 * session, only where the record has none, as audit-log lets a contributor fill
 * only a gap.
 *
 * Audit-log's own actor contributor runs first, and reads a user only from a
 * guard using Laravel's `GuardHelpers`, which `laravel-authentication`'s guards
 * do not, so on a `jwt` or `api_key` guard holding a caller it fills no actor
 * and leaves it to this contributor. The caller is the one a package guard
 * already holds (`HeldCaller`), read as audit-log walks the guards, the first
 * holding a user deciding, and only what the guard has bound: it never triggers
 * authentication, never calls `Auth::caller()` nor the guard's authentication
 * context, and reads no request. A guard that is not configured, or a tenant
 * that cannot be loaded, is read as no caller, or no tenant: audit-log loses a
 * record whose contributor throws, and a gap is better than no record.
 *
 * In a queued job no guard holds the dispatcher's caller: the worker reset
 * (IAM-11.3) forgets every package guard's binding before each job, so a guard
 * holding a caller there holds one the job bound itself, and nothing is ever
 * re-resolved from a request that is not there. Audit-log carries no actor of a
 * package guard's into the job either, since it cannot read one. So the caller
 * is carried into the job's payload by this package (`CarryCallerIntoJobs`),
 * and while the job runs, with no guard holding a
 * caller, the caller the job carried (`JobCallers`) is the one filled from;
 * outside a job none is.
 *
 * The caller is snapshotted as `laravel-authentication` snapshots it for its
 * own events (`CallerSnapshot`, from its `EventContext`): each model's morph
 * class, else its class name, the identity's auth identifier, the principal's
 * reference, the active tenant's tenant identifier and the session's
 * identifier. Its references are then made as the mappers make theirs
 * (`References`), each type read through the application's morph map and the
 * tenant named by its identifier under `References::TENANT_TYPE`, so a record
 * this contributor fills names the same people as one a mapper described.
 *
 * What it fills follows who the record is about. A record whose actor is still
 * open is the caller's: the actor and everything else is filled. A record whose
 * actor is already the caller (a mapper's) gets only the rest. A record whose
 * actor is someone else, or explicitly no one (`by(null)`, a failed sign-in or
 * a sweep), gets nothing, so the caller's principal, tenant or session never
 * lands on another person's record. The credential IAM-9.7 lists is the
 * mappers' alone (`usingCredential()`), since audit-log offers a contributor no
 * credential filler and the guard exposes no credential's id.
 *
 * It is registered with audit-log (`AuditLog::contribute()`) by
 * `AuditRegistrations`, is resolved from the current container for every
 * capture, and keeps nothing between captures (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallerContextContributor implements ContextContributor
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Audit\HeldCaller  $held
     * @param  \SineMacula\Laravel\Iam\Audit\JobCallers  $jobs
     */
    public function __construct(

        /** The caller a guard holds now. */
        private HeldCaller $held,

        /** The caller each job running carried. */
        private JobCallers $jobs,
    ) {}

    /**
     * Fill the caller's actor, guard, principal, tenant and session where the
     * record has none, while the record's actor is open or is the caller.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
     * @return void
     *
     * @throws \LogicException
     */
    #[\Override]
    public function contribute(Contribution $contribution): void
    {
        $caller   = $this->held->current() ?? $this->jobs->current();
        $identity = self::reference(static fn (): ?Reference => References::of($caller?->identityType, $caller?->identityId));

        if ($caller === null || $identity === null) {
            return;
        }

        if ($contribution->isActorSettled()) {

            $actor = $contribution->actor();

            if ($actor === null || !$actor->equals($identity)) {
                return;
            }
        }

        $contribution->fillActor($identity);
        $contribution->fillPrincipal(self::reference(static fn (): ?Reference => References::of($caller->principalType, $caller->principalId)));
        $contribution->fillTenant(self::reference(static fn (): ?Reference => References::tenant($caller->tenantId)));

        self::fillChecked(static fn () => $contribution->fillGuard($caller->guard));
        self::fillChecked(static fn () => $contribution->fillSession($caller->sessionId));
    }

    /**
     * The reference `References` gives the part, or `null` when it gives none
     * or audit-log cannot refer to it.
     *
     * @param  \Closure(): ?\SineMacula\Laravel\AuditLog\Records\Reference  $reference
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @param-immediately-invoked-callable $reference
     */
    private static function reference(\Closure $reference): ?Reference
    {
        try {
            return $reference();
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * Run a filler, leaving its field open when audit-log refuses the value (a
     * guard name or a session reference it cannot store).
     *
     * @param  \Closure(): void  $fill
     * @return void
     *
     * @param-immediately-invoked-callable $fill
     */
    private static function fillChecked(\Closure $fill): void
    {
        try {
            $fill();
        } catch (\InvalidArgumentException) {
            // The field stays open: a value audit-log cannot store would lose
            // the whole record
        }
    }
}
