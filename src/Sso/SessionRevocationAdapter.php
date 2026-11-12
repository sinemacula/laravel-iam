<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Tenancy\SubtreePolicyChanges;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * SSO's session revocation: each scope ends exactly its sessions through
 * `laravel-authentication`'s matching helper, inside SSO's transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionRevocationAdapter implements SessionRevocation
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \SineMacula\Laravel\Iam\Tenancy\SubtreePolicyChanges  $policyChanges
     */
    public function __construct(

        /** Resolves the session service the revocations go through. */
        private CurrentSession $sessions,

        /** Resolves the identity an identity scope names. */
        private IdentityReferences $identities,

        /** Judges the enforcing tenant's subtree in SSO's transaction, and once more once it commits. */
        private SubtreePolicyChanges $policyChanges,
    ) {}

    /**
     * Revoke the sessions of the scope, inside SSO's transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function revoke(RevocationScope $scope): void
    {
        match ($scope->kind) {
            RevocationScopeKind::TENANT              => $this->policyChanges->changed($scope->tenantId),
            RevocationScopeKind::CONNECTION          => $this->connection($scope),
            RevocationScopeKind::IDENTITY_CONNECTION => $this->sessions()->linkRemoved($this->identity($scope), self::connectionOf($scope), self::linkOf($scope)),
            RevocationScopeKind::IDENTITY_LINK       => $this->sessions()->linkScopeWidened($this->identity($scope), self::connectionOf($scope), self::linkOf($scope)),
        };
    }

    /**
     * End the connection's sessions, as disabled or deleted.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return int
     *
     * @throws \LogicException
     */
    private function connection(RevocationScope $scope): int
    {
        $connectionId = self::connectionOf($scope);

        return match ($scope->reason) {
            RevocationReason::CONNECTION_DISABLED => $this->sessions()->connectionDisabled($connectionId),
            RevocationReason::CONNECTION_DELETED  => $this->sessions()->connectionDeleted($connectionId),
            default                               => throw new \LogicException(sprintf('A connection\'s sessions are not revoked for [%s].', $scope->reason->value)),
        };
    }

    /**
     * The identity an identity scope names.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function identity(RevocationScope $scope): Identity
    {
        return $this->identities->identity($scope->identity ?? throw self::incomplete($scope, 'identity'));
    }

    /**
     * The session service every revocation goes through.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function sessions(): SessionService
    {
        return $this->sessions->identitySessions();
    }

    /**
     * The connection a connection or identity scope names.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return string
     *
     * @throws \LogicException
     */
    private static function connectionOf(RevocationScope $scope): string
    {
        return $scope->connectionId ?? throw self::incomplete($scope, 'connection');
    }

    /**
     * The link an identity scope names.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return string
     *
     * @throws \LogicException
     */
    private static function linkOf(RevocationScope $scope): string
    {
        return $scope->linkId ?? throw self::incomplete($scope, 'link');
    }

    /**
     * The refusal of a scope missing what its kind names.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @param  string  $part
     * @return \LogicException
     */
    private static function incomplete(RevocationScope $scope, string $part): \LogicException
    {
        return new \LogicException(sprintf('A revocation scope of the kind [%s] names its %s.', $scope->kind->value, $part));
    }
}
