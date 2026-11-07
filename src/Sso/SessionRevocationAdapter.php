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
 * SSO's session revocation, ending `laravel-authentication`'s sessions inside
 * the transaction SSO makes its change in (IAM-4.4, mandatory).
 *
 * Each of SSO's four scopes goes to the one helper of
 * `laravel-authentication`'s that ends exactly those sessions, on every guard:
 *
 * - `tenant` (`enforcement_changed`): the strict cut-off of
 *   `laravel-authentication`'s `tenantPolicyChanged()` for the tenant SSO
 *   names, the enforcing tenant, and for every tenant below it in the
 *   application's tenant tree, which may inherit its rule
 *   (`SubtreePolicyChanges`): it judges every session acting in each of them
 *   against the tenant authentication policy as it now answers, inside SSO's
 *   transaction, and once more once that transaction has committed, since a
 *   session that entered the tenant while the first pass ran (a password or
 *   passkey sign-in, a switch into the tenant, a sign-in through another
 *   tenant's connection, none of which takes SSO's lock of the rule) is not
 *   among the rows the first pass locked; every session the first pass recorded
 *   at the version it answered is skipped. No setting turns either off. SSO
 *   names only the enforcing tenant, so the tenants that inherit its rule come
 *   from the tree: every tenant below it, a tenant nearer that has a rule of
 *   its own among them, which is broader than the tenants that inherit it and
 *   never narrower. Without a tree every tenant stands alone and only the
 *   enforcing tenant is judged; an application that binds an enforcement
 *   inheritance of its own with no tree configured leaves the tenants that
 *   inherit unjudged. The whole subtree is resolved before any of it is judged.
 * - `connection` (`connection_disabled`, `connection_deleted`):
 *   `connectionDisabled()` or `connectionDeleted()`, each behind
 *   `laravel-authentication`'s own switch for it.
 * - `identity_connection` (`link_removed`): `linkRemoved()` for the identity,
 *   the connection and the link SSO removed, behind `laravel-authentication`'s
 *   own switch.
 * - `identity_link` (`scope_widened`): `linkScopeWidened()`, never the
 *   switchable `linkRemoved()`, so no setting turns it off; a second call for
 *   one widening finds nothing left to end, so SSO may report it twice.
 *
 * Each tenant resolves through `laravel-authentication`'s tenant resolver
 * (`TenantReferences`) and the identity through the morph map
 * (`IdentityReferences`); either one unresolved throws
 * `UnresolvedReferenceException` (IAM-8.2), a tree that cannot list the subtree
 * throws, and a scope missing what its kind names throws a `LogicException`, so
 * SSO's change rolls back rather than leave sessions standing that it meant to
 * end. Each helper runs as a savepoint of SSO's transaction, on the shared
 * storage connection, after SSO's locks, locking the session rows last (a
 * connection's or a link's after `laravel-authentication`'s connection guard
 * rows); it throws on failure and reports each revocation once the change
 * commits, so nothing is reported that was not done. The count each returns is
 * not SSO's concern. The tenant's second pass, for the subtree listed and
 * resolved anew from the tree as it then stands, a tenant moved under the
 * enforcing one while the change was open among it, is held for the commit of
 * the innermost transaction open on the storage connection, never another
 * connection's, and is dropped with the change when it rolls back. It runs only
 * once every callback queued on that transaction has run, SSO's report of the
 * change (`EnforcementChanged`) among them, since it opens a transaction of its
 * own, and SSO drops an event whose callback finds an outermost transaction
 * begun after its own; what it throws propagates from the commit, the change
 * already durable and reported. A commit callback that fails, before it or
 * after it (a listener of `EnforcementChanged`, say), leaves the change durable
 * and the second pass held, and it runs as the request, the command or the job
 * ends.
 *
 * No scope names a session or a guard, so the revocations go through
 * `laravel-authentication`'s session service for a change to the identity as a
 * whole (`CurrentSession::identitySessions()`); every helper ends the sessions
 * of every guard alike. Stateless (IAM-8.1).
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
     * End every session established through the connection, as disabled or as
     * deleted.
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
