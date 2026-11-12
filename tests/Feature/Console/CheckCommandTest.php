<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use SineMacula\Laravel\Iam\Checks\Checker;
use SineMacula\Laravel\Iam\Console\CheckCommand;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Scheduling\IamSchedule;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Concerns\MigratesAuditLog;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\TestCase;

/**
 * Feature tests for `iam:check`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckCommand::class)]
final class CheckCommandTest extends TestCase
{
    use MigratesAuditLog;

    /**
     * A fully configured application passes every check and exits zero.
     *
     * @return void
     */
    public function testAConfiguredApplicationPasses(): void
    {
        $this->configure();

        [$code, $output] = $this->check();

        self::assertSame(0, $code, $output);

        foreach ([...Checker::MEMBER_COMMANDS, 'iam'] as $header) {
            self::assertMatchesRegularExpression('/^' . preg_quote($header, '/') . '$/m', $output);
        }

        foreach (['storage', 'seams', 'context', 'audit', 'configuration', 'schedule'] as $subject) {
            self::assertStringContainsString("[{$subject}] OK", $output);
        }

        self::assertStringContainsString('[sso] not applied', $output);
        self::assertStringEndsWith('Every check passed.' . PHP_EOL, $output);
    }

    /**
     * MFA's default on a mandatory seam fails the run under `seams`.
     *
     * @return void
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    public function testMfasDefaultLeftOnAMandatorySeamFailsTheRun(): void
    {
        $this->configure();

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertStringContainsString('[seams] ' . SessionRevoker::class . ' is still bound to its member\'s', $output);
        self::assertStringEndsWith('A check failed.' . PHP_EOL, $output);
    }

    /**
     * While SSO is in use, its side is reported once under `sso`.
     *
     * @return void
     */
    public function testSsosSideIsChecked(): void
    {
        $this->configure();

        $config = $this->app?->make('config');

        $config?->set('sso.features.saml2', true);
        $config?->set('sso.applications.api.unlinked_handoffs', true);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);

        $problems = [
            '`sso.applications.api` is served by SSO, but its guard does not list `external_provider` among laravel-authentication\'s sign-in methods.',
            '`sso.applications.api.unlinked_handoffs` must stay off under laravel-iam: an unlinked result is provisioned or refused, never handed off.',
        ];

        foreach ($problems as $problem) {
            self::assertStringContainsString('[sso] ' . $problem, $output);
            self::assertSame(1, substr_count($output, $problem));
        }
    }

    /**
     * A member's own failing check fails the run.
     *
     * @return void
     */
    public function testAMembersFailureFailsTheRun(): void
    {
        $this->configure();

        $config = $this->app?->make('config');

        $config?->set('audit-log.storage.connection', 'nowhere');

        [$code, $output] = $this->check();

        // audit-log's migrations are rolled back on its connection
        $config?->set('audit-log.storage.connection', null);

        self::assertSame(1, $code, $output);
        self::assertStringContainsString('[storage] note: `audit-log.storage.connection` names another connection', $output);
        self::assertStringEndsWith('A check failed.' . PHP_EOL, $output);
    }

    /**
     * A member that never registered is reported missing and fails the run.
     *
     * @return void
     */
    public function testAMemberThatNeverRegisteredFailsTheRun(): void
    {
        $this->withArguments(['artisan', CheckCommand::NAME]);
        $this->reorderProviders([
            AuthenticationServiceProvider::class,
            AuthorizationServiceProvider::class,
            MfaServiceProvider::class,
            SsoServiceProvider::class,
            IamServiceProvider::class,
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code, $output);
        self::assertStringContainsString('audit-log:check is not registered.', $output);
    }

    /**
     * A storage mismatch fails the run instead of refusing boot.
     *
     * @return void
     */
    #[DefineEnvironment('pointMfaElsewhere')]
    public function testAStorageMismatchIsReportedRatherThanRefusedAtBoot(): void
    {
        $this->configure();

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertMatchesRegularExpression('/^\[storage\] .*mfa\.storage\.connection/m', $output);
    }

    /**
     * A broken authorization setting is reported by its check, not at boot.
     *
     * @return void
     */
    #[DefineEnvironment('breakAnAuthorizationSetting')]
    public function testABrokenAuthorizationSettingIsReportedRatherThanRefusedAtBoot(): void
    {
        $this->configure();

        [$code, $output] = $this->check();

        self::assertSame(1, $code, $output);
        self::assertStringContainsString('bulk.chunk_size', $output);
        self::assertStringEndsWith('A check failed.' . PHP_EOL, $output);
    }

    /**
     * Break an authorization setting with `iam:check` as the command.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    protected function breakAnAuthorizationSetting(Application $app): void
    {
        $this->withArguments(['artisan', CheckCommand::NAME]);

        $app->make('config')->set('authorization.bulk.chunk_size', 'lots');
    }

    /**
     * Point MFA's storage elsewhere with `iam:check` as the command.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    protected function pointMfaElsewhere(Application $app): void
    {
        $this->withArguments(['artisan', CheckCommand::NAME]);

        $config = $app->make('config');

        $config->set('database.connections.elsewhere', ['driver' => 'sqlite', 'database' => ':memory:']);
        $config->set('mfa.storage.connection', 'elsewhere');
    }

    /**
     * Configure what the suite needs and the members ship without.
     *
     * @return void
     */
    private function configure(): void
    {
        $config = $this->app?->make('config');

        $config?->set(CaptureExclusions::EXCEPT_GUARDS_KEY, ['api']);
        $config?->set(AuditSettings::REQUIRE_REGISTERED, true);

        /** @var array<string, mixed> $freshness */
        $freshness = $config?->get('authentication.freshness');

        foreach (Operation::cases() as $operation) {
            $freshness[$operation->value] = ['max_age_seconds' => 900, 'proofs' => ['additional_factor', 'recovery_code']];
        }

        $config?->set('authentication.freshness', $freshness);

        $app = $this->app;

        assert($app !== null);

        $app->instance(TenantResolver::class, new OpenTenancy);

        $app->make(IamSchedule::class)->register($app->make(Schedule::class));
    }

    /**
     * Run `iam:check`, and return its exit code and what it printed.
     *
     * @return array{int, string}
     */
    private function check(): array
    {
        $output = new BufferedOutput;
        $code   = Artisan::call(CheckCommand::NAME, [], $output);

        return [$code, $output->fetch()];
    }
}
