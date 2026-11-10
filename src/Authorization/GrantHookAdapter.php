<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Database\DeadlockException;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Exceptions\TransactionConflictException;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Tenancy\ScopeWidenings;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * `laravel-authorization`'s grant hook, answered by SSO's scope widening
 * (IAM-6.7, AUTHZ-11.3, SSO-8.8): before a grant that widens an identity's
 * scope is written, the identity's links by a verified domain in every other
 * tenant's connections are suspended, their reservations deleted and the
 * sessions established through them revoked, in the grant's own transaction.
 *
 * `laravel-authorization` calls it inside the grant call's transaction, on its
 * connection, before it takes any lock of its own, with every grant of the call
 * that widens the identity's scope. For each distinct tenant those grants hold
 * in, the tenant's id (`TenantTranslator::idOf()`, the key
 * `laravel-authorization` names it by, which this package takes as the
 * identifier SSO names it by once it resolves back to the same tenant), or
 * `null` for a platform-wide grant, it reports the widening through this
 * package's scope widening service (`Iam::scopeWidenings()->widen()`), which
 * runs SSO's `widened()` in a savepoint of that transaction, so SSO's identity
 * guard, its first lock, is taken before `laravel-authorization`'s, as SSO's
 * lock order asks. A tenant whose key, resolved through
 * `laravel-authentication`'s tenant resolver as an identifier, does not name
 * that same tenant by type and key refuses the grant
 * (`UnresolvedReferenceException::forGrantTenant()`): taken on trust, a key
 * that is another tenant's identifier would spare that other tenant's links
 * from suspension. A grant to the identity itself, which holds across every
 * principal of it, always widens, and so does a principal's first grant in a
 * tenant, so every such grant in a tenant needs that resolver: while this hook
 * is bound, `iam:check` refuses `laravel-authentication`'s `ResolveNoTenant`
 * (`Checks\CrossMemberConfigurationCheck`), which would refuse every one.
 *
 * The hooks the application lists in `authorization.grant_hooks` are not run
 * here: `laravel-authorization` wraps whatever grant hook is bound in them
 * (`ListedGrantHooks`, N108), so they run first, in order, and this adapter
 * after them, and binding it over the default drops none of them. Whatever any
 * of them throws refuses the grant: the whole call rolls back, the suspensions
 * and revocations with it, and nothing is dispatched.
 *
 * SSO's `widened()` refuses with a `LogicException` unless a transaction is
 * open on SSO's storage connection, so `authorization.connection` must name the
 * storage connection (this package aligns it, `Storage\StorageConnection`): a
 * grant call on another connection is refused here, never written without its
 * widening. SSO refuses a widening whose identity's links by a verified domain
 * changed after the transaction's snapshot was taken, before it could lock them
 * (`LinkCandidatesChanged`), which only a new transaction finds; the
 * classifier's plain reads take that snapshot before the hook runs, so a link
 * committed in between meets it. `laravel-authorization` tries a delegated call
 * again only for a concurrency error, so the refusal is handed on as Laravel's
 * `DeadlockException`, with the SQLSTATE of a serialisation failure (`40001`)
 * and SSO's refusal as its cause: a delegated call that opened its own
 * transaction is tried again from the start, and one inside a transaction the
 * application opened reaches it as `TransactionConflictException`.
 * `laravel-authorization` never tries a trusted call again for a concurrency
 * error, so a trusted grant made outside any transaction reaches the
 * application as that `DeadlockException`; made inside `Iam::transaction()`, or
 * Laravel's `DB::transaction()` given attempts, the whole transaction is tried
 * again, as for any serialisation failure. A call may therefore run the hook
 * more than once; every widening is written in the call's transaction and
 * rolled back with it, and SSO reports a suspension only once its transaction
 * commits, so nothing leaves a try that is rolled back.
 *
 * The widening is handed to it as a value alone: the identity named by its
 * morph type and key, resolved through the morph map on the write connection
 * (`IdentityReferences`), an identity that cannot be resolved throwing
 * `UnresolvedReferenceException` (IAM-8.2), so the grant is refused rather than
 * written with no widening reported. Only an identity whose type names an
 * Eloquent model of `laravel-authentication`'s `Identity` contract is resolved
 * and reported: one of any other kind, such as the user model of an admin panel
 * on a Laravel session guard, which `laravel-authorization`'s subject resolver
 * answers as its own identity (`SubjectResolverAdapter::forUser()`), is one SSO
 * never links, so SSO holds nothing of it to suspend, and its widening is not
 * reported to SSO at all, nor its tenants resolved, as `SubtreeGrantees` passes
 * such a grantee over on a move; the hooks the application lists still run for
 * it. `laravel-authorization`'s widening carries no client, so the suspensions
 * are reported for a client of which nothing is known
 * (`new ClientContext(null, null)`), as a job's are; the contract leaves no
 * other way, and nothing of the request is read in its place. It reads no
 * request, nor the current user, and keeps nothing between calls (IAM-8.1), so
 * it is transient.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantHookAdapter implements GrantHook
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \SineMacula\Laravel\Iam\Tenancy\ScopeWidenings  $widenings
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $tenants
     */
    public function __construct(

        /** Resolves the identity the grants widen. */
        private IdentityReferences $identities,

        /** Reports each widening to SSO in the grant's transaction. */
        private ScopeWidenings $widenings,

        /** Names each tenant the grants hold in by the id SSO names it by. */
        private TenantTranslator $tenants,
    ) {}

    /**
     * Report the widening to SSO for each tenant the widening grants hold in;
     * throw to refuse the grant.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    #[\Override]
    public function beforeWidening(GrantWidening $widening): void
    {
        if (!$this->identities->namesIdentity($widening->identity->type)) {
            return;
        }

        $this->reportToSso($widening);
    }

    /**
     * Report the widening to SSO for each tenant the widening grants hold in,
     * for the `laravel-authentication` identity it names.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     *
     * @throws \Throwable
     */
    private function reportToSso(GrantWidening $widening): void
    {
        $identity = $this->identities->identity(new IdentityReference($widening->identity->type, $widening->identity->id));
        $client   = new ClientContext(null, null);

        foreach ($this->tenantsOf($widening) as $tenantId) {
            $this->widen($identity, $tenantId, $client);
        }
    }

    /**
     * Report the widening to SSO for one tenant, handing SSO's refusal of link
     * candidates that changed under its lock on as Laravel's concurrency error,
     * which `laravel-authorization` tries again.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $tenantId
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     *
     * @throws \Throwable
     */
    private function widen(Identity $identity, ?string $tenantId, ClientContext $client): void
    {
        try {
            $this->widenings->widen($identity, $tenantId, $client);
        } catch (LinkCandidatesChanged $changed) {
            throw self::concurrencyError($changed);
        }
    }

    /**
     * SSO's refusal of link candidates that changed under its lock, as
     * Laravel's concurrency error with the SQLSTATE of a serialisation failure,
     * SSO's refusal kept as its cause.
     *
     * @param  \SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged  $changed
     * @return \Illuminate\Database\DeadlockException
     */
    private static function concurrencyError(LinkCandidatesChanged $changed): DeadlockException
    {
        return new DeadlockException($changed->getMessage(), TransactionConflictException::SERIALIZATION_FAILURE, $changed);
    }

    /**
     * The id SSO names the tenant a grant holds in by, refused as the grant's
     * tenant when it does not resolve back to that same tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function idOf(Reference $tenant): string
    {
        try {
            return $this->tenants->idOf($tenant);
        } catch (UnresolvedReferenceException) {
            throw UnresolvedReferenceException::forGrantTenant($tenant->id);
        }
    }

    /**
     * The distinct tenants the widening grants hold in, each once, in the order
     * the grants name them: a tenant's id, or `null` for a platform-wide grant.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return list<?string>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function tenantsOf(GrantWidening $widening): array
    {
        $tenants = [];

        foreach ($widening->changes as $change) {

            $tenantId = $change->tenant === null ? null : $this->idOf($change->tenant);

            if (in_array($tenantId, $tenants, true)) {
                continue;
            }

            $tenants[] = $tenantId;
        }

        return $tenants;
    }
}
