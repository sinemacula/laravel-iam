<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * SSO's freshness contract, answered by `laravel-authentication`'s freshness
 * policy with SSO's maximum age as the caller's requirement (IAM-4.6, SSO-2.12,
 * AUTH-3.11).
 *
 * The operation is named as SSO gives it (`sso.link.create`, `sso.keys.rotate`
 * and the rest, which are valid operation names to `laravel-authentication`),
 * and SSO's maximum age becomes a requirement of that age alone, met by a proof
 * of any kind (`FreshnessRequirement::within()`), so the stricter of it and
 * whatever the application configures for the operation applies, and SSO's
 * requirement holds where the application configures none. The session is
 * `fresh` only when the policy finds a proof that meets that requirement now;
 * otherwise, or with no session to judge, it is `stale`.
 *
 * SSO hands the contract the caller the action is taken for
 * (`Identities\Caller`), and the adapter judges that caller alone, never the
 * request, the default guard or the session a guard serves: the session judged
 * is the one the caller names by its key, found among its identity's own
 * sessions (`CurrentSession::owned()`), of whichever guard, and the policy
 * judges it only while it is live and active. No caller (a scheduled job, a
 * console command), a caller with no session, and a session that is not the
 * caller's identity's are `stale` without the policy being asked. An identity
 * reference that names no identity throws `UnresolvedReferenceException`
 * (IAM-8.2).
 *
 * The policy is asked plainly, reading the session again on the write
 * connection and taking no lock. SSO asks its freshness contract inside its own
 * transactions, a `link` redemption's after its link locks and before the
 * application's eligibility and confirmation contracts, whose guards come
 * before the session's row in SSO's lock order; a current judgement would lock
 * the session's row there and invert that order. A plain read inside a
 * transaction may answer from its snapshot (MySQL's `REPEATABLE READ`), so this
 * package names a caller with its session only while no transaction is open on
 * the storage connection (`Callers::of()`), and a `link` redeemed inside the
 * caller's transaction with none (`LinkRedemption`): such a caller is `stale`.
 * An application that names an operation's requirement more strictly configures
 * it in `laravel-authentication`.
 *
 * Freshness renewed through a verified domain link, or through its connection,
 * is not the person's independent confirmation of that link: that is link
 * confirmation's to judge (IAM-4.10), never this contract's. It keeps nothing
 * between calls (IAM-8.1): the identity and its session are read on each one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FreshnessAdapter implements Freshness
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy  $freshness
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     */
    public function __construct(

        /** Judges the session's freshness. */
        private FreshnessPolicy $freshness,

        /** Finds the caller's session among its identity's own. */
        private CurrentSession $sessions,

        /** Resolves the identity SSO names. */
        private IdentityReferences $identities,
    ) {}

    /**
     * Whether the caller's session is fresh for the operation within SSO's
     * maximum age; `stale` for no caller.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function check(FreshnessOperation $operation, int $maxAgeSeconds, ?Caller $caller): FreshnessOutcome
    {
        $requirement = FreshnessRequirement::within($maxAgeSeconds);
        $session     = $this->session($caller);

        return $session !== null && $this->freshness->freshProof($session, $operation->value, $requirement) !== null
            ? FreshnessOutcome::FRESH
            : FreshnessOutcome::STALE;
    }

    /**
     * The session judged: the one the caller names, among its identity's own,
     * or `null` for no caller, a caller with no session, or a session that is
     * not its identity's.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function session(?Caller $caller): ?Session
    {
        if ($caller === null || $caller->sessionId === null) {
            return null;
        }

        return $this->sessions->owned($this->identities->identity($caller->identity), $caller->sessionId);
    }
}
