<?php

declare(strict_types = 1);

namespace Tests\Unit\Sso;

use Illuminate\Config\Repository;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy as AuthenticationApplicationPolicy;
use SineMacula\Laravel\Iam\Sso\ApplicationPolicyAdapter;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn;

/**
 * Unit tests for SSO's application policy over `laravel-authentication`'s
 * sign-in methods.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationPolicyAdapter::class)]
final class ApplicationPolicyAdapterTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Rows of whether the guard allows `external_provider`, SSO's own setting,
     * and the answer.
     *
     * @return iterable<string, array{0: bool, 1: bool, 2: \SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn}>
     */
    public static function provideMethodLists(): iterable
    {
        yield 'allowed, SSO\'s setting on' => [true, true, ExternalSignIn::ALLOWED];

        yield 'allowed, SSO\'s setting off' => [true, false, ExternalSignIn::ALLOWED];

        yield 'not allowed, SSO\'s setting on' => [false, true, ExternalSignIn::NOT_ALLOWED];

        yield 'not allowed, SSO\'s setting off' => [false, false, ExternalSignIn::NOT_ALLOWED];
    }

    /**
     * The guard's method list alone decides, whatever SSO's setting says.
     *
     * @param  bool  $allowed
     * @param  bool  $setting
     * @param  \SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn  $answer
     * @return void
     */
    #[DataProvider('provideMethodLists')]
    public function testTheGuardsMethodListAloneDecides(bool $allowed, bool $setting, ExternalSignIn $answer): void
    {
        $policy = \Mockery::mock(AuthenticationApplicationPolicy::class);

        $policy->expects('allowsMethod')->with('portal', 'external_provider')->andReturn($allowed);

        self::assertSame($answer, (new ApplicationPolicyAdapter($policy))->externalSignIn(self::application('portal', $setting)));
    }

    /**
     * A guard `laravel-authentication` does not know propagates its
     * `InvalidArgumentException`.
     *
     * @return void
     */
    public function testAGuardAuthenticationCannotJudgePropagates(): void
    {
        $policy = \Mockery::mock(AuthenticationApplicationPolicy::class);

        $policy->expects('allowsMethod')->andThrow(new \InvalidArgumentException('No such guard.'));

        $this->expectExceptionObject(new \InvalidArgumentException('No such guard.'));

        (new ApplicationPolicyAdapter($policy))->externalSignIn(self::application('unknown', true));
    }

    /**
     * An SSO application of the name, with SSO's own external sign-in setting.
     *
     * @param  string  $name
     * @param  bool  $externalSignIn
     * @return \SineMacula\Laravel\Sso\Applications\Application
     */
    private static function application(string $name, bool $externalSignIn): Application
    {
        return Application::fromSettings(new Repository, $name, ['redirect_uri' => 'https://app.iam.test/sso', 'external_sign_in' => $externalSignIn]);
    }
}
