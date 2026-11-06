<?php

declare(strict_types = 1);

namespace Tests\Feature\Mfa;

use Orchestra\Testbench\Foundation\Env;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Exceptions\CookieTransportUnsupportedException;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionCheck;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Fixtures\Providers\CarriesRefreshTokensInACookie;
use Tests\TestCase;

/**
 * Feature tests for refusing an application whose pending sign-ins this
 * package's pending completion could never complete: one booting with the
 * completion bound beside a session guard whose refresh token travels in a
 * cookie, where `laravel-authentication` refuses every completion MFA makes as
 * `cross_site_request`. An application that carries every refresh token in the
 * body, binds its own completion, or turns the MFA capability off boots, and so
 * does one while a configuration command runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingCompletionCheck::class)]
#[CoversClass(IamServiceProvider::class)]
final class PendingCompletionCheckTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var list<string> The environment variables this test set, cleared once its application is destroyed. */
    private array $environment = [];

    /**
     * Destroy the application, then clear the environment variables the test
     * set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        foreach ($this->environment as $name) {
            Env::forget($name);
        }
    }

    /**
     * With this package's pending completion bound, a session guard whose
     * refresh token travels in a cookie refuses boot, in every provider order,
     * naming that guard and not the one that carries it in the body.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('provideProviderOrders')]
    public function testACookieGuardRefusesBootWithThePendingCompletionBound(array $providers): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->expectException(CookieTransportUnsupportedException::class);
        $this->expectExceptionMessage('The guard [' . CarriesRefreshTokensInACookie::GUARD . '] carries its refresh token in a cookie');

        $this->bootInOrder([...$providers, CarriesRefreshTokensInACookie::class]);
    }

    /**
     * An application whose session guards all carry the refresh token in the
     * body boots with this package's pending completion bound.
     *
     * @return void
     */
    public function testABodyApplicationBootsWithThePendingCompletionBound(): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class]);

        self::assertInstanceOf(PendingCompletionAdapter::class, $this->completion());
    }

    /**
     * An application that binds its own pending completion, once every provider
     * has registered, is left alone beside a cookie guard: it completes its
     * pending sign-ins its own way.
     *
     * @return void
     */
    public function testAnApplicationsOwnCompletionIsLeftAlone(): void
    {
        $this->withArguments(self::CHECKED_COMMAND);

        $providers = [...self::MEMBER_PROVIDERS, IamServiceProvider::class, CarriesRefreshTokensInACookie::class];

        $this->bootInOrder($providers, after: [PendingCompletion::class => ProofStoreCompletion::class]);

        self::assertInstanceOf(ProofStoreCompletion::class, $this->completion());
    }

    /**
     * With the MFA capability turned off, nothing of this package's completes a
     * pending sign-in, and a cookie guard boots.
     *
     * @return void
     */
    public function testACookieGuardBootsWithTheMfaCapabilityOff(): void
    {
        $this->withArguments(self::CHECKED_COMMAND);
        $this->withEnvironment(['IAM_ADAPTERS_MFA' => 'false']);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, CarriesRefreshTokensInACookie::class]);

        self::assertNotInstanceOf(PendingCompletionAdapter::class, $this->completion());
    }

    /**
     * While a console command that lists, describes, discovers, caches or
     * clears configuration runs, a cookie guard is not refused, so the
     * configuration can still be inspected and cleared.
     *
     * @return void
     */
    public function testACookieGuardIsNotRefusedWhileAConfigurationCommandRuns(): void
    {
        $this->withArguments(['artisan', 'config:clear']);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, CarriesRefreshTokensInACookie::class]);

        self::assertInstanceOf(PendingCompletionAdapter::class, $this->completion());
    }

    /**
     * The pending completion the booted application builds.
     *
     * @return mixed
     */
    private function completion(): mixed
    {
        $abstract = PendingCompletion::class;
        $app      = $this->app;

        self::assertNotNull($app);
        self::assertTrue($app->isBooted());

        return $app->make($abstract);
    }

    /**
     * Set environment variables for the next application, to be cleared once
     * the test ends.
     *
     * @param  array<string, string>  $variables
     * @return void
     */
    private function withEnvironment(array $variables): void
    {
        foreach ($variables as $name => $value) {
            Env::set($name, $value);

            $this->environment[] = $name;
        }
    }
}
