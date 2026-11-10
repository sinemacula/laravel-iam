<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Console\ConfigurationChecks;
use SineMacula\Laravel\Authentication\Console\ConfigurationFinding;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Iam\Checks\AuthenticationConfigurationCheck;
use SineMacula\Laravel\Iam\Checks\Checker;
use SineMacula\Laravel\Iam\Checks\ContextNamespacesCheck;
use SineMacula\Laravel\Iam\Checks\CrossMemberConfigurationCheck;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Checks\StorageCheck;
use SineMacula\Laravel\Iam\Console\CheckCommand;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Mfa\Enums\Operation;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Fixtures\Checks\ScriptedCheck;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\TestCase;

/**
 * Feature tests for reporting this package's checks of
 * `laravel-authentication`'s side in `authentication:check` (IAM-10.3): an
 * error fails the command, `--guard` limits the findings about a guard, a check
 * that throws is reported by its class alone, the check is registered once, and
 * `iam:check` reports each problem once, under `iam`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationConfigurationCheck::class)]
#[CoversClass(IamServiceProvider::class)]
final class AuthenticationConfigurationCheckTest extends TestCase
{
    /** @var string Why MFA's operations undeclared for a guard are refused, the guard elided. */
    private const string UNDECLARED = '[iam:configuration] MFA\'s freshness operations [mfa.add_factor] are not declared for guard [%s]';

    /**
     * An error of this package's fails `authentication:check`, reported under
     * the guard it is about; with nothing found, the command passes and reports
     * nothing of this package's.
     *
     * @return void
     */
    public function testAnErrorFailsAuthenticationCheck(): void
    {
        $this->declareMfaOperations();

        [$code, $output] = $this->authenticationCheck();

        self::assertSame(0, $code, $output);
        self::assertStringNotContainsString('[iam:', $output);

        $this->app?->make('config')->set('auth.guards.api.freshness', ['mfa.add_factor' => null]);

        [$code, $output] = $this->authenticationCheck();

        self::assertSame(1, $code);
        self::assertStringContainsString('[api] ' . sprintf(self::UNDECLARED, 'api'), $output);
    }

    /**
     * `--guard` limits the findings about a guard to the guards it names.
     *
     * @return void
     */
    public function testTheGuardOptionLimitsIt(): void
    {
        $this->declareMfaOperations();

        $config = $this->app?->make('config');

        $config?->set('auth.guards.admin', [...(array) $config->get('auth.guards.api'), 'freshness' => ['mfa.add_factor' => null]]);
        $config?->set('mfa.applications.admin', $config->get('mfa.applications.api'));

        [$code, $output] = $this->authenticationCheck();

        self::assertSame(1, $code, $output);
        self::assertStringContainsString('[admin] ' . sprintf(self::UNDECLARED, 'admin'), $output);

        [$code, $output] = $this->authenticationCheck(['api']);

        self::assertSame(0, $code, $output);
        self::assertStringNotContainsString('[iam:', $output);

        [$code, $output] = $this->authenticationCheck(['admin']);

        self::assertSame(1, $code);
        self::assertStringContainsString('[admin] ' . sprintf(self::UNDECLARED, 'admin'), $output);
    }

    /**
     * Each closure is graded as `iam:check` grades it: one that throws is an
     * error, a note a warning, and anything else nothing; those about no one
     * guard come first, then those about each guard checked, and a check that
     * does not apply answers nothing.
     *
     * @return void
     */
    public function testEachClosureIsGradedAsIamCheckGradesIt(): void
    {
        $this->script(StorageCheck::class, new ScriptedCheck('first', [
            static fn () => throw new \LogicException('A problem.'),
            static fn (): string => 'A note.',
            static fn (): string => '',
            static fn (): int => 1,
        ], guardChecks: [
            'api'   => [static fn () => throw new \LogicException('A problem of the guard.')],
            'admin' => [static fn (): string => 'Not checked.'],
        ]));
        $this->script(MandatorySeamsCheck::class, new ScriptedCheck('second', [static fn (): string => 'Another note.']));
        $this->script(ContextNamespacesCheck::class, new ScriptedCheck('skipped', [static fn () => throw new \LogicException('Not run.')], false));
        $this->script(CrossMemberConfigurationCheck::class, new ScriptedCheck('last'));

        self::assertEquals([
            ConfigurationFinding::error('[iam:first] A problem.'),
            ConfigurationFinding::warning('[iam:first] A note.'),
            ConfigurationFinding::error('[iam:first] A problem of the guard.', 'api'),
            ConfigurationFinding::warning('[iam:second] Another note.'),
        ], $this->adapter()->findings(['api']));
    }

    /**
     * A check that cannot be resolved, or whose closures cannot be built, is
     * reported by its class and the class of the exception, never the
     * exception's message, and the checks after it still run.
     *
     * @return void
     */
    public function testAThrowingCheckIsContained(): void
    {
        $this->app?->bind(StorageCheck::class, static fn () => throw new \RuntimeException('a value'));
        $this->script(MandatorySeamsCheck::class, new ScriptedCheck('seams', failure: new \LogicException('another value')));
        $this->script(ContextNamespacesCheck::class, new ScriptedCheck('context', [static fn () => throw new \LogicException('A problem.')]));

        $findings = $this->adapter()->findings([]);

        self::assertEquals([
            ConfigurationFinding::error('The check [' . StorageCheck::class . '] failed: RuntimeException.'),
            ConfigurationFinding::error('The check [' . MandatorySeamsCheck::class . '] failed: LogicException.'),
            ConfigurationFinding::error('[iam:context] A problem.'),
        ], array_slice($findings, 0, 3));

        [$code, $output] = $this->authenticationCheck();

        self::assertSame(1, $code);
        self::assertStringContainsString('The check [' . StorageCheck::class . '] failed: RuntimeException.', $output);
        self::assertStringNotContainsString('a value', $output);
    }

    /**
     * The check is registered with `authentication:check` once, and again,
     * once, with each instance of `laravel-authentication`'s checks built.
     *
     * @return void
     */
    public function testNothingIsRegisteredTwice(): void
    {
        $app = $this->app;

        assert($app !== null);

        $registered = static fn (): array => array_keys($app->make(ConfigurationChecks::class)->registered(), AuthenticationConfigurationCheck::class, true);

        self::assertCount(1, $registered());
        self::assertCount(1, $registered());

        $app->forgetInstance(ConfigurationChecks::class);

        self::assertCount(1, $registered());
    }

    /**
     * `iam:check` reports a problem of this package's once, under `iam`, not
     * under `authentication:check` too, which reports it again once `iam:check`
     * has finished.
     *
     * @return void
     */
    public function testIamCheckReportsEachProblemOnce(): void
    {
        $this->declareMfaOperations();

        $this->app?->make('config')->set('auth.guards.api.freshness', ['mfa.add_factor' => null]);

        $output = new BufferedOutput;

        self::assertSame(1, Artisan::call(CheckCommand::NAME, [], $output));

        $printed = $output->fetch();

        self::assertSame(1, substr_count($printed, 'MFA\'s freshness operations [mfa.add_factor]'), $printed);
        self::assertStringNotContainsString('[iam:', $printed);
        self::assertFalse($this->app?->make(Checker::RUNNING));

        [$code, $printed] = $this->authenticationCheck();

        self::assertSame(1, $code);
        self::assertStringContainsString(sprintf(self::UNDECLARED, 'api'), $printed);
    }

    /**
     * Declare MFA's freshness operations under `laravel-authentication`'s
     * freshness, so every MFA application's guard passes, and bind a tenant
     * resolver that resolves, so the tenant resolver passes.
     *
     * @return void
     */
    private function declareMfaOperations(): void
    {
        // With the authorization and SSO adapters both on, a widening grant
        // resolves its tenant, so the tenant resolver must resolve
        $this->app?->instance(TenantResolver::class, new OpenTenancy);

        $config = $this->app?->make('config');

        /** @var array<string, mixed> $freshness */
        $freshness = $config?->get('authentication.freshness');

        foreach (Operation::cases() as $operation) {
            $freshness[$operation->value] = ['max_age_seconds' => 900, 'proofs' => ['additional_factor', 'recovery_code']];
        }

        $config?->set('authentication.freshness', $freshness);
    }

    /**
     * Bind one of the checks the adapter runs to a scripted one.
     *
     * @param  class-string  $check
     * @param  \Tests\Fixtures\Checks\ScriptedCheck  $scripted
     * @return void
     */
    private function script(string $check, ScriptedCheck $scripted): void
    {
        $this->app?->instance($check, $scripted);
    }

    /**
     * The adapter, resolved as `authentication:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\AuthenticationConfigurationCheck
     */
    private function adapter(): AuthenticationConfigurationCheck
    {
        $adapter = $this->app?->make(AuthenticationConfigurationCheck::class);

        assert($adapter instanceof AuthenticationConfigurationCheck);

        return $adapter;
    }

    /**
     * Run `authentication:check`, limited to the guards given, and return its
     * exit code and what it printed.
     *
     * @param  list<string>  $guards
     * @return array{int, string}
     */
    private function authenticationCheck(array $guards = []): array
    {
        $output = new BufferedOutput;
        $code   = Artisan::call('authentication:check', $guards === [] ? [] : ['--guard' => $guards], $output);

        return [$code, $output->fetch()];
    }
}
