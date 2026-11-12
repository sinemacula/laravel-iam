<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Iam\Checks\ContextNamespacesCheck;
use SineMacula\Laravel\Iam\Mfa\MfaContextContributor;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Sso\SsoContextContributor;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use Tests\Concerns\RunsChecks;
use Tests\TestCase;

/**
 * Feature tests for the context namespaces check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextNamespacesCheck::class)]
final class ContextNamespacesCheckTest extends TestCase
{
    use RunsChecks;

    /**
     * The check asks for `sso` only while SSO is in use.
     *
     * @return void
     */
    public function testItRequiresSsoOnlyWhileSsoIsInUse(): void
    {
        self::assertTrue($this->check()->applies());
        self::assertSame('context', $this->check()->subject());
        self::assertCount(1, $this->check()->checks());

        $this->app?->make('config')->set('sso.features.saml2', true);

        self::assertTrue($this->check()->applies());
        self::assertCount(2, $this->check()->checks());
    }

    /**
     * This package's own contributors pass.
     *
     * @return void
     */
    public function testThePackagesContributorPasses(): void
    {
        $this->app?->make('config')->set('sso.features.oidc', true);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * SSO in use without an `sso` contributor fails.
     *
     * @return void
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testANamespaceNobodyRegisteredFails(): void
    {
        $this->app?->make('config')->set('sso.features.saml2', true);

        $problem = 'No contributor is registered under the `sso` namespace of the authentication context; turn `iam.adapters.sso` on, or register your own.';

        self::assertSame([$problem], self::problems($this->check()->checks()));

        $this->app?->make(ContextContributors::class)->register('sso', SsoContextContributor::class);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * No `mfa` contributor fails, whether or not SSO is in use.
     *
     * @return void
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    public function testAnMfaNamespaceNobodyRegisteredFails(): void
    {
        $problem = 'No contributor is registered under the `mfa` namespace of the authentication context; turn `iam.adapters.mfa` on, or register your own.';

        self::assertSame([$problem], self::problems($this->check()->checks()));

        $this->app?->make('config')->set('sso.features.oidc', true);

        self::assertSame([$problem], self::problems($this->check()->checks()));

        $this->app?->make(ContextContributors::class)->register('mfa', MfaContextContributor::class);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * The check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\ContextNamespacesCheck
     */
    private function check(): ContextNamespacesCheck
    {
        $check = $this->app?->make(ContextNamespacesCheck::class);

        assert($check instanceof ContextNamespacesCheck);

        return $check;
    }
}
