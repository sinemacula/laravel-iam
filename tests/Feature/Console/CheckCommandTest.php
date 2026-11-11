<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use SineMacula\Laravel\Iam\Checks\Checker;
use SineMacula\Laravel\Iam\Checks\SsoCheckRegistration;
use SineMacula\Laravel\Iam\Console\CheckCommand;
use SineMacula\Laravel\Iam\Scheduling\IamSchedule;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Sso\Config\Checks\FeaturesCheck;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Concerns\MigratesAuditLog;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\TestCase;

/**
 * Feature tests for `iam:check` (IAM-10.1): it runs every member's check and
 * this package's own, reports each, and exits non-zero on any failure; and the
 * storage refusal at boot stands aside for it, so it reports a mismatch rather
 * than stopping before it can.
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
     * An application configured as the suite needs it, its tables migrated and
     * the package's schedule registered, passes every check and exits zero.
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

        foreach (['storage', 'seams', 'context', 'audit', 'senders', 'configuration', 'platform', 'schedule'] as $subject) {
            self::assertStringContainsString("[{$subject}] OK", $output);
        }

        self::assertStringContainsString('[sso] not applied', $output);
        self::assertStringContainsString('[iam] not enabled', $output);
        self::assertStringEndsWith('Every check passed.' . PHP_EOL, $output);
    }

    /**
     * A problem of this package's own fails the run, with the problem reported
     * under its subject.
     *
     * @return void
     */
    public function testAProblemOfThePackagesOwnFailsTheRun(): void
    {
        $this->configure();

        $this->app?->bind(SessionRevocation::class, NoSessionRevocation::class);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertStringContainsString('[seams] ' . SessionRevocation::class . ' is still bound to ' . NoSessionRevocation::class, $output);
        self::assertStringEndsWith('A check failed.' . PHP_EOL, $output);
    }

    /**
     * Rows of how `sso:check` comes not to run this package's check of SSO's
     * side: the application keeps a check of its own under its subject, or
     * binds a checker of its own that runs SSO's checks alone.
     *
     * @return iterable<string, array{\Closure(\Illuminate\Contracts\Foundation\Application): void}>
     */
    public static function bridgeNotInForce(): iterable
    {
        yield 'the application\'s own check under the subject' => [static function (Application $app): void {
            $checks = [...SsoServiceProvider::CONFIGURATION_CHECKS, SsoCheckRegistration::SUBJECT => FeaturesCheck::class];

            $app->instance(ConfigurationChecks::class, new ConfigurationChecks($checks));
        }];
        yield 'a checker of the application\'s' => [static function (Application $app): void {
            $app->bind(ConfigurationChecker::class, static fn (Application $app): ConfigurationChecker => new ConfigurationChecker($app, SsoServiceProvider::CONFIGURATION_CHECKS));
        }];
    }

    /**
     * While SSO is in use and `sso:check` does not run this package's check of
     * SSO's side, `iam:check` runs it itself: an application handing off
     * unlinked results, and one whose guard does not allow an external sign-in,
     * fail the run, each reported once.
     *
     * @param  \Closure(\Illuminate\Contracts\Foundation\Application): void  $takeOut
     * @return void
     */
    #[DataProvider('bridgeNotInForce')]
    public function testSsosSideIsCheckedWhenSsosCheckDoesNotRunIt(\Closure $takeOut): void
    {
        $this->configure();

        $config = $this->app?->make('config');

        $config?->set('sso.features.saml2', true);
        $config?->set('sso.applications.api.unlinked_handoffs', true);

        $app = $this->app;

        assert($app !== null);

        $takeOut($app);

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
     * A member's own check failing fails the run, though this package's checks
     * find only a note: audit-log's storage on a connection nobody configures.
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
     * A member key on another connection does not stop `iam:check` at boot: it
     * is reported, and the run fails.
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
     * A broken `laravel-authorization` setting does not stop `iam:check` at
     * boot: `laravel-authorization` boots for diagnosis under it, and its own
     * check reports the setting and fails the run.
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
     * Give `laravel-authorization` a bulk chunk size that is no number, with
     * `iam:check` as the process's command, before any provider registers.
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
     * Point MFA's storage at another connection, with `iam:check` as the
     * process's command, before any provider registers.
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
     * Configure what the suite needs and the members ship without: audit-log's
     * exclusions and refusal of unregistered codes, MFA's operations declared
     * under `laravel-authentication`'s freshness, a tenant resolver, which the
     * grant hook names a widening grant's tenant through, the package's
     * schedule, and audit-log's spill channel in its documented format.
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
