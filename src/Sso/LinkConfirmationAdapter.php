<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Sessions\Provenance as SsoProvenance;

/**
 * SSO's link confirmation (IAM-4.10): the caller's session is `independent`
 * only when its first factor was a password, a passkey or the application's own
 * recovery, it holds no provider re-authentication, and its provenance names no
 * link of verified domain provenance.
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

        /** Finds the caller's session and tells whether a transaction is open. */
        private CurrentSession $sessions,

        /** Resolves the identity SSO names. */
        private IdentityReferences $identities,
    ) {}

    /**
     * Whether the caller's session is independent of every verified domain
     * link: signed in with a password, a passkey or the application's own
     * recovery, never renewed through a provider, and recording no link of
     * verified domain provenance.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  list<string>  $domainLinkIds
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function judge(Caller $caller, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict
    {
        unset($connection, $domainLinkIds);

        $session = $this->session($caller);
        $guard   = $session?->getGuard();

        return $session !== null && in_array($guard, Auth::sessionGuards(), true) && $this->isIndependent(Auth::sessions($guard), $session)
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
     * application's own recovery, holds no counting proof of a provider's
     * re-authentication, and records no link of verified domain provenance.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionService  $service
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    private function isIndependent(SessionService $service, EloquentSession&Model $session): bool
    {
        $firstFactor = $service->firstFactor($session);

        return $firstFactor !== null
            && in_array($firstFactor->channel->kind, self::INDEPENDENT_CHANNELS, true)
            && $service->proofs($session, kinds: [ProofKind::EXTERNAL_REAUTHENTICATION]) === []
            && !self::namesADomainLink($service->provenance($session));
    }

    /**
     * Whether the session's recorded provenance names a link of verified domain
     * provenance, as SSO stored it in the provider context; never for a session
     * with no provenance or no provider context.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Provenance  $provenance
     * @return bool
     *
     * @throws \UnexpectedValueException
     */
    private static function namesADomainLink(?Provenance $provenance): bool
    {
        $stored = $provenance?->providerContext?->toArray();

        return $stored !== null && SsoProvenance::restore($stored)->linkProvenance === LinkOrigin::VERIFIED_DOMAIN;
    }
}
