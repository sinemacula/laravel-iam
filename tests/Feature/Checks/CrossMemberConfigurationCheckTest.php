<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use SineMacula\Laravel\Iam\Checks\AuditCheck;
use SineMacula\Laravel\Iam\Checks\CrossMemberConfigurationCheck;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Iam\Checks\StorageCheck;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Sso\Config\Checks\EndpointsCheck;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use Tests\Concerns\RunsChecks;
use Tests\TestCase;

/**
 * Feature tests for the configuration that crosses the members (IAM-2.5),
 * bullet by bullet: the ones this check holds (MFA's applications and the
 * members' freshness operations), and the ones held where they belong, SSO's by
 * the check SSO's own runs and audit-log's by the audit check, so every bullet
 * is pinned here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CrossMemberConfigurationCheck::class)]
final class CrossMemberConfigurationCheckTest extends TestCase
{
    use RunsChecks;

    /** @var string Why MFA's operations undeclared for the guard the tests sign in on are refused. */
    private const string UNDECLARED = 'MFA\'s freshness operations [%s] are not declared for guard [api] under `authentication.freshness` or the guard\'s `freshness`.';

    /**
     * MFA's operations, undeclared under `laravel-authentication`'s freshness
     * as it ships, are refused for the MFA application's guard; declared, they
     * pass.
     *
     * @return void
     */
    public function testMfasOperationsMustBeDeclared(): void
    {
        $operations = 'mfa.add_factor, mfa.replace_factor, mfa.remove_factor, mfa.generate_recovery_codes';

        self::assertSame([sprintf(self::UNDECLARED, $operations)], self::problems($this->check()->checks()));

        $this->declare(array_column(Operation::cases(), 'value'));

        self::assertSame([], self::problems($this->check()->checks()));
        self::assertTrue($this->check()->applies());
        self::assertSame('configuration', $this->check()->subject());
    }

    /**
     * An operation is declared by the guard's own freshness block too, and
     * removed there by `null`.
     *
     * @return void
     */
    public function testTheGuardsOwnBlockDeclaresAndRemoves(): void
    {
        $config = $this->app?->make('config');

        $this->declare(['mfa.add_factor', 'mfa.replace_factor', 'mfa.remove_factor']);

        $config?->set('auth.guards.api.freshness', ['mfa.generate_recovery_codes' => ['max_age_seconds' => 300, 'proofs' => ['additional_factor']], 'mfa.add_factor' => null]);

        self::assertSame([sprintf(self::UNDECLARED, 'mfa.add_factor')], self::problems($this->check()->checks()));

        $config?->set('auth.guards.api.freshness', 'not a block');
        $config?->set('authentication.freshness', 'not a block');

        self::assertCount(1, self::problems($this->check()->checks()));
    }

    /**
     * Every MFA application must name a guard: MFA's application is the guard
     * of the same name, one listed rather than named included.
     *
     * @return void
     */
    public function testEveryMfaApplicationMustBeAGuard(): void
    {
        $this->declare(array_column(Operation::cases(), 'value'));

        $this->app?->make('config')->set('mfa.applications.admin', ['types' => ['totp']]);

        self::assertSame(['`mfa.applications.admin` names no guard in `auth.guards`: MFA\'s application is the guard of the same name.'], self::problems($this->check()->checks()));

        $this->app?->make('config')->set('mfa.applications', [['types' => ['totp']]]);

        self::assertSame(['`mfa.applications.0` names no guard in `auth.guards`: MFA\'s application is the guard of the same name.'], self::problems($this->check()->checks()));
    }

    /**
     * With no MFA application and SSO out of use, nothing is required.
     *
     * @return void
     */
    public function testNoApplicationsRequireNothing(): void
    {
        $this->app?->make('config')->set('mfa.applications', null);

        self::assertSame([], $this->check()->checks());
    }

    /**
     * While SSO is in use, SSO's operations must be declared for each SSO
     * application's guard; out of use, they are not required.
     *
     * @return void
     */
    public function testSsosOperationsMustBeDeclaredWhileSsoIsInUse(): void
    {
        $config = $this->app?->make('config');

        $this->declare(array_column(Operation::cases(), 'value'));

        $config?->set('sso.applications', ['api' => []]);

        self::assertSame([], self::problems($this->check()->checks()));

        $config?->set('sso.features.saml2', true);

        $problems = self::problems($this->check()->checks());

        self::assertCount(1, $problems);
        self::assertStringStartsWith('SSO\'s freshness operations [sso.connection.trust, ', $problems[0]);

        $this->declare([...array_column(Operation::cases(), 'value'), ...array_column(FreshnessOperation::cases(), 'value')]);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * SSO's bullets are each held once: every application SSO serves allowing
     * `external_provider` and none handing off an unlinked result by the check
     * SSO's own runs; the base URL set by SSO's own endpoints check, which
     * `sso:check` runs too; and the storage connection the shared one by the
     * storage check.
     *
     * @return void
     */
    public function testSsosBulletsAreHeldBySsosCheck(): void
    {
        $config = $this->app?->make('config');

        $config?->set('sso.features.saml2', true);
        $config?->set('sso.applications', ['api' => ['unlinked_handoffs' => true]]);
        $config?->set('sso.endpoints.base_url', null);

        self::assertSame([
            '`sso.applications.api` is served by SSO, but its guard does not list `external_provider` among laravel-authentication\'s sign-in methods.',
            '`sso.applications.api.unlinked_handoffs` must stay off under laravel-iam: an unlinked result is provisioned or refused, never handed off.',
        ], self::problems($this->bridge()->checks()));

        $endpoints = $this->app?->make(EndpointsCheck::class);

        assert($endpoints instanceof EndpointsCheck);

        self::assertStringStartsWith('`sso.endpoints.base_url` must be', self::problems($endpoints->checks())[0]);

        $config?->set('database.connections.elsewhere', ['driver' => 'sqlite', 'database' => ':memory:']);
        $config?->set('sso.storage.connection', 'elsewhere');

        $storage = $this->app->make(StorageCheck::class);

        self::assertCount(1, array_filter(self::problems($storage->checks()), static fn (string $problem): bool => str_contains($problem, 'sso.storage.connection')));
        self::assertSame([], array_filter(self::problems($this->bridge()->checks()), static fn (string $problem): bool => str_contains($problem, 'sso.')
            && !str_contains($problem, 'sso.applications')));
    }

    /**
     * Audit-log's bullets are held by the audit check: every `jwt` and
     * `api_key` guard excluded from its capture, its Gate capture off and its
     * refusal of unregistered codes on.
     *
     * @return void
     */
    public function testAuditLogsBulletsAreHeldByTheAuditCheck(): void
    {
        $config = $this->app?->make('config');

        $config?->set(CaptureExclusions::GATE_KEY, true);

        self::assertCount(3, self::problems($this->audit()->checks()));

        $config?->set(CaptureExclusions::EXCEPT_GUARDS_KEY, ['*']);
        $config?->set(CaptureExclusions::GATE_KEY, false);
        $config?->set(AuditSettings::REQUIRE_REGISTERED, true);

        self::assertSame([], self::problems($this->audit()->checks()));
    }

    /**
     * Declare the operations under `laravel-authentication`'s freshness, the
     * shipped ones kept.
     *
     * @param  list<string>  $operations
     * @return void
     */
    private function declare(array $operations): void
    {
        $config = $this->app?->make('config');

        /** @var array<string, mixed> $freshness */
        $freshness = $config?->get('authentication.freshness');

        foreach ($operations as $operation) {
            $freshness[$operation] = ['max_age_seconds' => 900, 'proofs' => ['additional_factor']];
        }

        $config?->set('authentication.freshness', $freshness);
    }

    /**
     * The check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\CrossMemberConfigurationCheck
     */
    private function check(): CrossMemberConfigurationCheck
    {
        $check = $this->app?->make(CrossMemberConfigurationCheck::class);

        assert($check instanceof CrossMemberConfigurationCheck);

        return $check;
    }

    /**
     * The check SSO's own runs for this package.
     *
     * @return \SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck
     */
    private function bridge(): SsoBridgeCheck
    {
        $check = $this->app?->make(SsoBridgeCheck::class);

        assert($check instanceof SsoBridgeCheck);

        return $check;
    }

    /**
     * The audit check.
     *
     * @return \SineMacula\Laravel\Iam\Checks\AuditCheck
     */
    private function audit(): AuditCheck
    {
        $check = $this->app?->make(AuditCheck::class);

        assert($check instanceof AuditCheck);

        return $check;
    }
}
