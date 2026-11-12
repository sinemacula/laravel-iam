<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * A break-glass exemption for the identities the test names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExemptsIdentities implements EnforcementExemption
{
    /** @var list<\SineMacula\Laravel\Sso\Identities\IdentityReference> The identities exempt. */
    private array $exempt = [];

    /** @var list<\SineMacula\Laravel\Sso\Identities\IdentityReference> Every identity asked about, in order. */
    private array $asked = [];

    /**
     * Exempt the identity from every tenant's enforcement.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return self
     */
    public function exempt(IdentityReference $identity): self
    {
        $this->exempt[] = $identity;

        return $this;
    }

    /**
     * Withdraw every exemption.
     *
     * @return self
     */
    public function exemptNobody(): self
    {
        $this->exempt = [];

        return $this;
    }

    /**
     * Whether the identity is one the test exempted.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome
     */
    #[\Override]
    public function exemption(EnforcementPolicy $policy, string $application, IdentityReference $identity): ExemptionOutcome
    {
        $this->asked[] = $identity;

        foreach ($this->exempt as $exempt) {

            if ($exempt->is($identity)) {
                return ExemptionOutcome::EXEMPT;
            }
        }

        return ExemptionOutcome::NOT_EXEMPT;
    }

    /**
     * Every identity asked about so far, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Identities\IdentityReference>
     */
    public function asked(): array
    {
        return $this->asked;
    }
}
