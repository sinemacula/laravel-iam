<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

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
 * SSO hands the contract neither the caller nor the application, and the
 * adapter never takes either from the request, the default guard or whoever a
 * guard happens to serve: the session judged is found only where this package
 * was handed them as plain values, in this request's record of callers
 * (`LinkCallers`). Inside a `link` redemption this package runs
 * (`LinkRedemption`), or the application's own call into SSO it hands the
 * caller in around (`CallerScope::run()`), it is the current session of the
 * application's guard when that guard serves the caller, and no session
 * otherwise. With no caller handed in (a `link` flow's start, a link's removal
 * or one of SSO's management helpers called without one, a queued job, a
 * console command) nothing is judged, and the answer is `stale`.
 *
 * The policy is asked plainly, reading the session again on the write
 * connection and taking no lock. SSO asks its freshness contract inside its own
 * transactions, a `link` redemption's after its link locks and before the
 * application's eligibility and confirmation contracts, whose guards come
 * before the session's row in SSO's lock order; a current judgement would lock
 * the session's row there and invert that order. A plain read inside a
 * transaction may answer from its snapshot (MySQL's `REPEATABLE READ`), so it
 * is trusted only from a transaction opened after the caller was handed in,
 * such as the one SSO opens for its own call, whose snapshot is no older than
 * the call: a caller handed in while a transaction was already open on the
 * storage connection (a `link` redeemed inside the caller's transaction) is
 * `stale` while a transaction is open, without asking the policy, since that
 * snapshot may still count a proof voided, or a session revoked, before the
 * call. An application that names an operation's requirement more strictly
 * configures it in `laravel-authentication`.
 *
 * Freshness renewed through a verified domain link, or through its connection,
 * is not the person's independent confirmation of that link: that is link
 * confirmation's to judge (IAM-4.10), never this contract's. It keeps nothing
 * between calls (IAM-8.1): the record of callers and the guard are read on each
 * one.
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
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy  $freshness
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     */
    public function __construct(

        /** Resolves the record of link callers on each call. */
        private Container $container,

        /** Judges the session's freshness. */
        private FreshnessPolicy $freshness,

        /** Resolves the guards and their sessions. */
        private CurrentSession $sessions,

        /** Names the identity a guard serves as SSO names it. */
        private IdentityReferences $identities,
    ) {}

    /**
     * Whether the caller's session is fresh for the operation within SSO's
     * maximum age.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function check(FreshnessOperation $operation, int $maxAgeSeconds): FreshnessOutcome
    {
        $requirement = FreshnessRequirement::within($maxAgeSeconds);
        $session     = $this->session();

        return $session !== null && $this->freshness->freshProof($session, $operation->value, $requirement) !== null
            ? FreshnessOutcome::FRESH
            : FreshnessOutcome::STALE;
    }

    /**
     * The session judged: the handed-in caller's on its application's guard, or
     * `null` when no caller is handed in, when the guard serves another
     * identity or none, or when the caller was handed in inside a transaction
     * that is still open.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function session(): ?Session
    {
        $caller = $this->container->make(LinkCallers::class)->current();

        if ($caller === null || ($caller['inTransaction'] && $this->sessions->isInTransaction())) {
            return null;
        }

        return $this->callersSession($caller['application'], $caller['caller']);
    }

    /**
     * The current session of the application's guard, when the guard serves the
     * caller, or `null` otherwise.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function callersSession(string $application, IdentityReference $caller): ?Session
    {
        $guard    = $this->sessions->guard($application);
        $identity = $guard->identity();

        return $identity !== null && $this->identities->reference($identity)->is($caller) ? $guard->session() : null;
    }
}
