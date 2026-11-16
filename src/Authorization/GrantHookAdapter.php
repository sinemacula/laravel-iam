<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Tenancy\ScopeWidenings;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Reports a widening grant to SSO's scope widening in the grant's transaction,
 * before `laravel-authorization` locks, as SSO's lock order asks.
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
     * Report the widening to SSO; throw to refuse the grant.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    #[\Override]
    public function beforeWidening(GrantWidening $widening): void
    {
        // SSO holds nothing of a grantee that is not an identity.
        if (!$this->identities->namesIdentity($widening->identity->type)) {
            return;
        }

        $this->reportToSso($widening);
    }

    /**
     * Report the widening to SSO for each tenant its grants hold in.
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

        foreach ($this->sparedOf($widening) as $spared) {
            $this->widenings->widen([$identity], $spared, $client);
        }
    }

    /**
     * The grant tenant's id, refused unless it resolves back to that tenant.
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
     * The distinct tenants the grants hold in, each spared alone; none spared
     * for platform-wide.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return list<list<string>>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function sparedOf(GrantWidening $widening): array
    {
        $spared = [];

        foreach ($widening->changes as $change) {

            $tenantIds = $change->tenant === null ? [] : [$this->idOf($change->tenant)];

            if (in_array($tenantIds, $spared, true)) {
                continue;
            }

            $spared[] = $tenantIds;
        }

        return $spared;
    }
}
