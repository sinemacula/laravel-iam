<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextAdapter;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\GrantHookAdapter;
use SineMacula\Laravel\Iam\Authorization\IdentityDirectoryAdapter;
use SineMacula\Laravel\Iam\Authorization\RequirementCheckerAdapter;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use Tests\Fixtures\Authorization\NamedIdentityDirectory;
use Tests\Fixtures\Authorization\NamedSubjectResolver;
use Tests\TestCase;

/**
 * Feature tests for declaring each authorization adapter to the config report.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationSeams::class)]
#[CoversClass(SeamBinding::class)]
#[CoversClass(Lifetime::class)]
final class DeclaredAuthorizationSeamsTest extends TestCase
{
    /** @var array<class-string, array{class-string, string}> Each contract declared, with the adapter declared and its lifetime. */
    private const array DECLARED = [
        SubjectResolver::class                  => [SubjectResolverAdapter::class, 'scoped'],
        AuthenticationContext::class            => [AuthenticationContextAdapter::class, 'transient'],
        AuthenticationRequirementChecker::class => [RequirementCheckerAdapter::class, 'transient'],
        SessionPolicySource::class              => [SessionPolicySourceAdapter::class, 'transient'],
        IdentityDirectory::class                => [IdentityDirectoryAdapter::class, 'transient'],
        GrantHook::class                        => [GrantHookAdapter::class, 'transient'],
    ];

    /** @var array<string, mixed> What the application sets in `laravel-authorization`'s configuration before any provider registers. */
    private array $authorization = [];

    /** @var bool Whether the application binds every declared contract itself, as its own provider's `register()` would. */
    private bool $bindsItsOwn = false;

    /**
     * Each adapter is declared, and `authorization:check` passes.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testEveryAdapterIsDeclaredAndStands(): void
    {
        $app          = $this->application();
        $declarations = Declarations::of($app);

        self::assertSame(array_keys(self::DECLARED), array_keys($declarations->all()));

        foreach (array_keys(self::DECLARED) as $contract) {
            self::assertSame($app->getBindings()[$contract]['concrete'], $declarations->for($contract)?->binding, $contract);
        }

        [$exit, $seams] = $this->report();

        self::assertSame(0, $exit);

        foreach (self::DECLARED as $contract => [$adapter, $lifetime]) {

            $seam = $seams[$contract];

            self::assertSame('declared', $seam['origin'], $contract);
            self::assertSame([$adapter], $seam['classes'], $contract);
            self::assertNull($seam['decides'], $contract);
            self::assertSame($lifetime, $seam['lifetime'], $contract);
            self::assertSame([
                'owner'    => AuthorizationSeams::OWNER,
                'classes'  => [$adapter],
                'decides'  => null,
                'lifetime' => $lifetime,
                'state'    => 'standing',
            ], $seam['declaration'], $contract);
        }
    }

    /**
     * The text report names the owner, the class and the lifetime.
     *
     * @return void
     */
    public function testTheTextReportNamesLaravelIam(): void
    {
        $output = $this->text();

        self::assertStringContainsString('[seam SubjectResolver] declared by laravel-iam; ' . SubjectResolverAdapter::class . '; scoped', $output);
        self::assertStringContainsString('[seam AuthenticationContext] declared by laravel-iam; ' . AuthenticationContextAdapter::class . '; transient', $output);
    }

    /**
     * Nothing is declared over the application's own binding.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testNothingIsDeclaredOverAnApplicationBinding(): void
    {
        $this->bindsItsOwn = true;

        $this->refreshApplication();

        self::assertSame([], Declarations::of($this->application())->all());

        [, $seams] = $this->report();

        foreach (array_keys(self::DECLARED) as $contract) {
            self::assertNull($seams[$contract]['declaration'], $contract);
        }
    }

    /**
     * A configured class is reported as configured and not declared over.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAConfiguredClassIsReportedAsConfigured(): void
    {
        $this->authorization = ['subject_resolver' => NamedSubjectResolver::class, 'identity_directory' => NamedIdentityDirectory::class];

        $this->refreshApplication();

        [, $seams] = $this->report();

        foreach ([SubjectResolver::class, IdentityDirectory::class] as $contract) {
            self::assertSame('configured', $seams[$contract]['origin'], $contract);
            self::assertNull($seams[$contract]['declaration'], $contract);
        }

        self::assertSame('standing', $seams[AuthenticationContext::class]['declaration']['state'] ?? null);
    }

    /**
     * With the switch off nothing is declared.
     *
     * @return void
     *
     * @throws \JsonException
     */
    #[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
    public function testWithTheSwitchOffNothingIsDeclared(): void
    {
        self::assertSame([], Declarations::of($this->application())->all());

        [, $seams] = $this->report();

        foreach (array_keys(self::DECLARED) as $contract) {
            self::assertNull($seams[$contract]['declaration'], $contract);
        }
    }

    /**
     * A row whose switch is off is not declared.
     *
     * @return void
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testARowWhoseSwitchIsOffIsNotDeclared(): void
    {
        $declared = array_diff(array_keys(self::DECLARED), [AuthenticationRequirementChecker::class, GrantHook::class]);

        self::assertSame(array_values($declared), array_keys(Declarations::of($this->application())->all()));
    }

    /**
     * Set what the test names in `laravel-authorization`'s configuration.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        foreach ($this->authorization as $key => $value) {
            $app->make('config')->set('authorization.' . $key, $value);
        }
    }

    /**
     * Seed the environment, then make the test's application bindings.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        if (!$this->bindsItsOwn) {
            return;
        }

        foreach (self::applicationBindings() as $contract => $binding) {
            $app->bind($contract, $binding);
        }
    }

    /**
     * A stand-in of the application's own for each contract declared.
     *
     * @return array<class-string, \Closure(): object>
     */
    private static function applicationBindings(): array
    {
        $bindings = [];

        foreach (array_keys(self::DECLARED) as $contract) {

            $instance = \Mockery::mock($contract);

            $instance->allows('namespaces')->andReturn(['authentication']);
            $instance->allows('assuranceKeys')->andReturn([]);

            $bindings[$contract] = static fn (): object => $instance;
        }

        return $bindings;
    }

    /**
     * Run `authorization:check` as JSON and return its exit code and seams.
     *
     * @return array{int, array<string, array<string, mixed>>}
     *
     * @throws \JsonException
     */
    private function report(): array
    {
        $exit   = Artisan::call('authorization:check', ['--format' => 'json']);
        $report = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($report);
        self::assertIsArray($report['seams'] ?? null);

        $seams = [];

        foreach ($report['seams'] as $seam) {
            self::assertIsArray($seam);
            self::assertIsString($seam['contract'] ?? null);

            $seams[$seam['contract']] = $seam;
        }

        return [$exit, $seams];
    }

    /**
     * Run `authorization:check` as text, and return what it printed.
     *
     * @return string
     */
    private function text(): string
    {
        Artisan::call('authorization:check');

        return Artisan::output();
    }

    /**
     * The application under test.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function application(): Application
    {
        return $this->app ?? self::fail('The application has not booted.');
    }
}
