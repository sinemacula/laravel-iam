<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Checks\MfaIdentityCheck;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Authorization\ServiceAccount;
use Tests\Fixtures\Authorization\Staff;
use Tests\TestCase;

/**
 * Feature tests for the MFA identity check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaIdentityCheck::class)]
final class MfaIdentityCheckTest extends TestCase
{
    use RunsChecks;

    /**
     * MFA's identities, machines on `jwt` guards and `api_key` guards pass.
     *
     * @return void
     */
    public function testMfaIdentitiesMachinesAndApiKeyGuardsPass(): void
    {
        $config = $this->app?->make('config');

        $config?->set('auth.providers.machines', ['driver' => 'model', 'model' => ServiceAccount::class]);
        $config?->set('auth.providers.staff', ['driver' => 'model', 'model' => Staff::class]);
        $config?->set('auth.guards.machines', ['driver' => 'jwt', 'provider' => 'machines']);
        $config?->set('auth.guards.staff', ['driver' => 'api_key', 'provider' => 'staff']);

        $check = $this->check();

        self::assertCount(2, $check->checks());
        self::assertSame([], self::problems($check->checks()));
        self::assertSame([], self::notes($check->checks()));
        self::assertTrue($check->applies());
        self::assertSame('identities', $check->subject());
    }

    /**
     * A person identity model of a `jwt` guard that is not MFA's identity is
     * refused by name.
     *
     * @return void
     */
    public function testAPersonWithoutMfaFails(): void
    {
        $config = $this->app?->make('config');

        $config?->set('auth.providers.staff', ['driver' => 'model', 'model' => Staff::class]);
        $config?->set('auth.guards.again', ['driver' => 'jwt', 'provider' => 'people']);
        $config?->set('auth.guards.staff', ['driver' => 'jwt', 'provider' => 'staff']);

        $checks  = $this->check()->checks();
        $problem = sprintf('The identity model %s of a `jwt` guard does not implement %s', Staff::class, MultiFactorAuthenticatable::class)
            . ', so each of its sign-ins throws while `iam.adapters.mfa` is on.';

        self::assertSame([0, 1], array_keys($checks));
        self::assertSame([$problem], self::problems($checks));
    }

    /**
     * The check stands aside while the MFA adapters are off.
     *
     * @return void
     */
    public function testTheCheckFollowsTheMfaSwitch(): void
    {
        $this->app?->make('config')->set('iam.adapters.mfa', false);

        self::assertFalse($this->check()->applies());
    }

    /**
     * The check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\MfaIdentityCheck
     */
    private function check(): MfaIdentityCheck
    {
        $check = $this->app?->make(MfaIdentityCheck::class);

        assert($check instanceof MfaIdentityCheck);

        return $check;
    }
}
