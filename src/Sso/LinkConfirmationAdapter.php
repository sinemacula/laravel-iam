<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
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
 * answers, was made over the `password` channel (a password sign-in) or the
 * `passkey` channel (a passkey sign-in), or it is the application's own
 * recovery, a session the application started through
 * `Auth::sessions($guard)->start()` under one of the sign-in methods it names
 * at `iam.sso.recovery_methods` (`RECOVERY_METHODS`), which
 * `laravel-authentication` records on the `unknown` channel. Its freshness must
 * not have been renewed through a provider either: a session holding a counting
 * `external_reauthentication` proof is `dependent`. Everything else is
 * `dependent`: a session an external provider established (its first factor on
 * the `external_provider` channel, whichever link it stood on and whatever that
 * link's provenance was or is now), a code sign-in (a mailbox or a phone number
 * of the organisation's domain is no more the person's own than its provider),
 * any other `start()`, a session whose first factor no longer counts, and every
 * session the reader does not answer for (a pending, revoked or ended one, a
 * machine's, another guard's).
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
 * SSO hands the contract no caller and no session, and the adapter never takes
 * one from the request, the default guard or the session a guard serves: the
 * session judged is found only where this package was handed the caller as a
 * plain value, `laravel-authentication`'s `Caller`, in this request's record of
 * callers (`LinkCallers`), as SSO's freshness is (`FreshnessAdapter`). Inside a
 * `link` redemption this package runs (`LinkRedemption`), or the application's
 * own call into SSO it hands the caller in around (`CallerScope::run()`), it is
 * the session the caller's access credential holds, when that is a session of
 * the caller's guard that the caller's identity owns
 * (`LinkCallers::sessionOf()`), and only when the caller is the identity SSO
 * asks about, byte for byte (`IdentityReferences::reference()`). With no caller
 * handed in, or a caller holding no session of its own, it is `dependent`.
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
 * (IAM-8.1): the record of callers, the configuration and the session's proofs
 * are read on each one, and an error propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkConfirmationAdapter implements LinkConfirmation
{
    /** @var string The setting naming the sign-in methods of the application's own recovery. */
    public const string RECOVERY_METHODS = 'iam.sso.recovery_methods';

    /** @var list<\SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind> The first factors' channels a person holds apart from every provider. */
    private const array INDEPENDENT_CHANNELS = [ChannelKind::PASSWORD, ChannelKind::PASSKEY];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Resolves the record of link callers on each call. */
        private Container $container,

        /** Resolves the caller's guard to its session service, and tells whether a transaction is open. */
        private CurrentSession $sessions,

        /** Names the caller's identity as SSO names the identity it asks about. */
        private IdentityReferences $identities,

        /** Holds the sign-in methods of the application's own recovery. */
        private Repository $config,
    ) {}

    /**
     * Whether the caller's session is independent of every verified domain
     * link: signed in with a password, a passkey or the application's own
     * recovery, and never renewed through a provider.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  list<string>  $domainLinkIds
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function judge(IdentityReference $identity, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict
    {
        unset($connection, $domainLinkIds);

        $caller = $this->container->make(LinkCallers::class)->current()['caller'] ?? null;

        if ($caller === null || !$this->sessions->isInTransaction()) {
            return LinkConfirmationVerdict::DEPENDENT;
        }

        $session = $this->sessionOf($caller, $identity);

        return $session !== null && $this->isIndependent($this->sessions->sessions($caller->guard), $session)
            ? LinkConfirmationVerdict::INDEPENDENT
            : LinkConfirmationVerdict::DEPENDENT;
    }

    /**
     * The caller's own session, when the caller is the identity SSO asks about,
     * or `null` otherwise.
     *
     * @param  \SineMacula\Laravel\Authentication\Callers\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function sessionOf(Caller $caller, IdentityReference $identity): (EloquentSession&Model)|null
    {
        return $this->identities->reference($caller->identity)->is($identity) ? LinkCallers::sessionOf($caller) : null;
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
            && $this->isHeldApart($firstFactor)
            && $service->proofs($session, kinds: [ProofKind::EXTERNAL_REAUTHENTICATION]) === [];
    }

    /**
     * Whether the first factor is one the person holds apart from every
     * provider: a password or a passkey sign-in, or a sign-in the application
     * started under one of its recovery methods.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @return bool
     */
    private function isHeldApart(RecordedProof $firstFactor): bool
    {
        $channel = $firstFactor->channel->kind;

        return in_array($channel, self::INDEPENDENT_CHANNELS, true)
            || ($channel === ChannelKind::UNKNOWN && $this->isRecovery($firstFactor->method));
    }

    /**
     * Whether the method is one the application names as its own recovery: one
     * the setting lists, which names none when it is anything but a list of
     * method names: a keyed array, or a list holding anything but strings, is
     * refused whole, never read in part.
     *
     * @param  string  $method
     * @return bool
     */
    private function isRecovery(string $method): bool
    {
        $methods = $this->config->get(self::RECOVERY_METHODS);

        return is_array($methods)
            && array_is_list($methods)
            && array_filter($methods, is_string(...)) === $methods
            && in_array($method, $methods, true);
    }
}
