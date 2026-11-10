<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;

/**
 * SSO's link confirmation contract, answered from how the caller's session was
 * established, as `laravel-authentication`'s public reader of a session's
 * proofs records it (IAM-4.10, IAM-13.9, SSO-8.8).
 *
 * The identity provider behind a verified domain link was never the person's
 * choice, so no session standing on such a link, in any connection, confirms
 * anything. The session is `independent` only when it was signed in with
 * something the person holds apart from every provider: its first factor, the
 * oldest counting first-factor proof `Auth::sessions($guard)->firstFactor()`
 * answers, was made over the `password` channel (a password sign-in), the
 * `passkey` channel (a passkey sign-in) or the `recovery` channel (the
 * application's own recovery, a session it started through
 * `Auth::sessions($guard)->start()` from a first factor on that channel, which
 * `laravel-authentication` admits as a first factor only). Its freshness must
 * not have been renewed through a provider either: a session holding a counting
 * `external_reauthentication` proof is `dependent`. Everything else is
 * `dependent`: a session an external provider established (its first factor on
 * the `external_provider` channel, whichever link it stood on and whatever that
 * link's provenance was or is now), a code sign-in (a mailbox or a phone number
 * of the organisation's domain is no more the person's own than its provider),
 * any other `start()` (one on the `unknown` channel among them), a session
 * whose first factor no longer counts, and every session the reader does not
 * answer for (a pending, revoked or ended one, a machine's, another guard's).
 *
 * SSO's own words for the rule are the session's recorded link provenance
 * (`sso.link_provenance`): a session that was not established through a link of
 * verified domain provenance. `laravel-authentication` records a provenance,
 * and SSO's link provenance inside it, only for a session an external provider
 * established, whose first factor is on the `external_provider` channel, so a
 * password, passkey or recovery session has none, and every session that has
 * one is `dependent` here: the first factor alone decides, and the provenance,
 * which `laravel-authentication` publishes to no other package outside its
 * context contributors, is not read. So a session through a link of no verified
 * domain provenance (one the person made with a `link`) is `dependent` too, as
 * FEATURES (IAM-4.10) names only a password, a passkey or the application's
 * recovery: stricter than SSO's contract allows, never looser. Nor are the
 * connection and the domain links SSO hands over read: no session this adapter
 * answers `independent` for stood on any link.
 *
 * SSO hands the contract the caller the redemption is made for
 * (`Identities\Caller`), whose identity it has checked is the one the code is
 * bound to, and the adapter judges that caller's session alone, never the
 * request, the default guard or the session a guard serves: the session the
 * caller names by its key, found among its identity's own sessions
 * (`CurrentSession::owned()`), and read through the public reader of the guard
 * it belongs to, which answers only for a live, active session of a person. A
 * caller with no session, a session that is not its identity's, and one of a
 * guard that holds no sessions are `dependent`. An identity reference that
 * names no identity throws `UnresolvedReferenceException` (IAM-8.2).
 *
 * SSO asks the contract inside a `link` redemption's transaction, in its
 * judgement and again in its admission, under the identity's guard and the
 * connections' and the links' locks, and after the application's eligibility,
 * whose guards come before the session's row in SSO's lock order. Inside a
 * transaction on the session model's connection the public reader locks the
 * session's row until the transaction ends and reads its proofs current, so the
 * answer holds until the redeemer commits by the lock every writer of the
 * session (a revocation, a sign-out, a factor's removal voiding its proofs)
 * takes first: the guard SSO's contract asks for. The session's row is the last
 * lock in SSO's order, so taking it there inverts nothing; at PostgreSQL's
 * REPEATABLE READ, a session changed since the transaction's snapshot fails to
 * serialise instead, and the redemption is retried (`LinkRedemption`). Outside
 * a transaction no such guard can be held, so the answer is `dependent` without
 * reading anything. It reads on the write connection, as the reader does, and
 * writes nothing.
 *
 * What a password, a passkey or a recovery proves is the application's to keep
 * true: a password or passkey enrolled from a session a verified domain link
 * established, or a recovery a provider can drive, proves nothing the provider
 * could not do (SSO's `docs/guides/links.md`). It keeps nothing between calls
 * (IAM-8.1): the caller's session and its proofs are read on each one, and an
 * error propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkConfirmationAdapter implements LinkConfirmation
{
    /** @var list<\SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind> The first factors' channels a person holds apart from every provider. */
    private const array INDEPENDENT_CHANNELS = [ChannelKind::PASSWORD, ChannelKind::PASSKEY, ChannelKind::RECOVERY];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     */
    public function __construct(

        /** Finds the caller's session among its identity's own, resolves its guard to its session service, and tells whether a transaction is open. */
        private CurrentSession $sessions,

        /** Resolves the identity SSO names. */
        private IdentityReferences $identities,
    ) {}

    /**
     * Whether the caller's session is independent of every verified domain
     * link: signed in with a password, a passkey or the application's own
     * recovery, and never renewed through a provider.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  list<string>  $domainLinkIds
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function judge(Caller $caller, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict
    {
        unset($connection, $domainLinkIds);

        $session = $this->session($caller);
        $guard   = $session?->getGuard();

        return $session !== null && in_array($guard, $this->sessions->sessionGuards(), true) && $this->isIndependent($this->sessions->sessions($guard), $session)
            ? LinkConfirmationVerdict::INDEPENDENT
            : LinkConfirmationVerdict::DEPENDENT;
    }

    /**
     * The caller's session, among its identity's own, or `null` for a caller
     * with no session, a session that is not its identity's, or any asked
     * outside a transaction, where no guard could be held.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function session(Caller $caller): (EloquentSession&Model)|null
    {
        if ($caller->sessionId === null || !$this->sessions->isInTransaction()) {
            return null;
        }

        return $this->sessions->owned($this->identities->identity($caller->identity), $caller->sessionId);
    }

    /**
     * Whether the session was signed in with a password, a passkey or the
     * application's own recovery, and holds no counting proof of a provider's
     * re-authentication.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionService  $service
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function isIndependent(SessionService $service, EloquentSession&Model $session): bool
    {
        $firstFactor = $service->firstFactor($session);

        return $firstFactor !== null
            && in_array($firstFactor->channel->kind, self::INDEPENDENT_CHANNELS, true)
            && $service->proofs($session, kinds: [ProofKind::EXTERNAL_REAUTHENTICATION]) === [];
    }
}
