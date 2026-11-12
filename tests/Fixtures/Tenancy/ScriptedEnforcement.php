<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;

/**
 * SSO's enforcement as the test scripts it, recording each question.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedEnforcement implements Enforcement
{
    /** @var ?array{connections: list<string>, version: string} The rule every tenant has, or `null` for none. */
    private ?array $rule = null;

    /** @var list<array{tenant: string, application: string}> Every question asked, in order. */
    private array $asked = [];

    /**
     * Require every session to come through one of the connections.
     *
     * @param  list<string>  $connections
     * @param  string  $version
     * @return self
     */
    public function requireThrough(array $connections, string $version = 'enforcement-1'): self
    {
        $this->rule = ['connections' => $connections, 'version' => $version];

        return $this;
    }

    /**
     * Require no connection of any session.
     *
     * @return self
     */
    public function requireNothing(): self
    {
        $this->rule = null;

        return $this;
    }

    /**
     * The policy the test last set, for the tenant asked about.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     */
    #[\Override]
    public function policy(string $tenantId, string $application): EnforcementPolicy
    {
        $this->asked[] = ['tenant' => $tenantId, 'application' => $application];

        return $this->rule === null
            ? EnforcementPolicy::notRequired($tenantId, $tenantId)
            : EnforcementPolicy::required($tenantId, $tenantId, $this->rule['connections'], $this->rule['version']);
    }

    /**
     * Every question asked so far, in order.
     *
     * @return list<array{tenant: string, application: string}>
     */
    public function asked(): array
    {
        return $this->asked;
    }
}
