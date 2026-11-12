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
 * (IAM-6.7, AUTHZ-11.3, SSO-8.8).
 *
 * It runs in the grant's transaction before `laravel-authorization` takes a
 * lock, so SSO's identity guard is taken first, as SSO's lock order asks. A
 * tenant whose key does not resolve back to that tenant refuses the grant, and
 * a grantee that is no `laravel-authentication` identity is passed over, as SSO
 * holds nothing of it. SSO's `LinkCandidatesChanged` is handed on as a
 * serialisation failure, which `laravel-authorization` tries again.
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
     * for the `laravel-authentication` identity it names and the client it
     * carries.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     *
     * @throws \Throwable
     */
    private function reportToSso(GrantWidening $widening): void
    {
        $identity = $this->identities->identity(new IdentityReference($widening->identity->type, $widening->identity->id));
        $client   = new ClientContext($widening->ip, $widening->userAgent);

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
            $this->widenings->widen([$identity], $tenantId, $client);
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
