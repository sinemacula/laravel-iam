<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine;
use SineMacula\Laravel\Iam\Checks\MachineMarkerCheck;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Authorization\ServiceAccount;
use Tests\Fixtures\Models\Machine;
use Tests\TestCase;

/**
 * Feature tests for the machine marker check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MachineMarkerCheck::class)]
final class MachineMarkerCheckTest extends TestCase
{
    use RunsChecks;

    /**
     * People and marked machines pass.
     *
     * @return void
     */
    public function testPeopleAndMarkedMachinesPass(): void
    {
        $this->app?->make('config')->set('auth.providers.service-accounts', ['driver' => 'model', 'model' => ServiceAccount::class]);
        $this->app?->make('config')->set('auth.guards.service-accounts', ['driver' => 'api_key', 'provider' => 'service-accounts']);

        $check = $this->check();

        self::assertSame([], self::problems($check->checks()));
        self::assertSame([], self::notes($check->checks()));
        self::assertTrue($check->applies());
        self::assertSame('machines', $check->subject());
    }

    /**
     * A machine identity model without the marker is refused by name.
     *
     * @return void
     */
    public function testAnUnmarkedMachineFails(): void
    {
        $this->app?->make('config')->set('auth.providers.machines', ['driver' => 'model', 'model' => Machine::class]);
        $this->app?->make('config')->set('auth.guards.again', ['driver' => 'jwt', 'provider' => 'people']);
        $this->app?->make('config')->set('auth.guards.machines', ['driver' => 'api_key', 'provider' => 'machines']);

        $checks  = $this->check()->checks();
        $problem = sprintf('The identity model %s implements %s without %s', Machine::class, MachineIdentity::class, AuthorizableMachine::class)
            . ', so laravel-authorization takes it for a person.';

        self::assertSame([0, 1], array_keys($checks));
        self::assertSame([$problem], self::problems($checks));
    }

    /**
     * The check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\MachineMarkerCheck
     */
    private function check(): MachineMarkerCheck
    {
        $check = $this->app?->make(MachineMarkerCheck::class);

        assert($check instanceof MachineMarkerCheck);

        return $check;
    }
}
