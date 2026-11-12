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
 * SSO's link confirmation: `independent` only for a session signed in with a
 * password, passkey or recovery and never renewed through a provider.
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
     * Whether the caller's session is independent of every domain link.
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
        // Unused: no session judged independent stood on any link.
        unset($connection, $domainLinkIds);

        $session = $this->session($caller);
        $guard   = $session?->getGuard();

        return $session !== null && in_array($guard, Auth::sessionGuards(), true) && $this->isIndependent(Auth::sessions($guard), $session)
            ? LinkConfirmationVerdict::INDEPENDENT
            : LinkConfirmationVerdict::DEPENDENT;
    }

    /**
     * The caller's own session, or `null` outside a transaction.
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
     * Whether the session was signed in and kept apart from every provider.
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
     * Whether the session's provenance names a verified domain link.
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
