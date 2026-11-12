<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Iam\Mfa\ActiveStateResolverAdapter;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ActiveStateResolverTests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Machine;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Tests for MFA's active state, read from `laravel-authentication`'s.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActiveStateResolverAdapter::class)]
final class ActiveStateResolverAdapterTest extends TestCase
{
    use ActiveStateResolverTests, MigratesMembers, SignsInPeople;

    /** @var string A connection whose reads go to a replica that lags its primary. */
    private const string REPLICATED = 'replicated';

    /**
     * A deactivatable identity is judged by its active state there.
     *
     * @return void
     */
    public function testAnIdentityAuthenticationCanDeactivateIsJudgedByItsActiveState(): void
    {
        foreach ([true, false] as $active) {

            $identity = self::activatable($active, !$active);

            self::assertSame(!$active, $identity->isMfaActive());
            self::assertSame($active, $this->adapter()->isActive($identity));
        }
    }

    /**
     * Any other identity answers by its own `isMfaActive()`.
     *
     * @return void
     */
    public function testAnyOtherIdentityAnswersAsMfasDefaultDoes(): void
    {
        $inactive = new class extends User implements MultiFactorAuthenticatable {
            use HasFactors;

            /**
             * Whether MFA's own reading takes the identity as active.
             *
             * @return bool
             */
            #[\Override]
            public function isMfaActive(): bool
            {
                return false;
            }
        };

        self::assertTrue($this->adapter()->isActive(new Machine));
        self::assertFalse($this->adapter()->isActive($inactive));
    }

    /**
     * The active state is read from the primary, never a lagging replica.
     *
     * @return void
     */
    public function testAnIdentityIsActiveAsThePrimaryHasIt(): void
    {
        $connection = DB::connection(self::REPLICATED);

        foreach ([$connection->getPdo(), $connection->getReadPdo()] as $pdo) {
            $pdo->exec('create table suspensions (identity_id integer not null)');
        }

        $connection->getPdo()->exec('insert into suspensions (identity_id) values (1)');

        $identity = new class extends User implements CanBeActive, MultiFactorAuthenticatable {
            use HasFactors;

            /**
             * Whether the identity has no suspension.
             *
             * @return bool
             */
            #[\Override]
            public function isActive(): bool
            {
                $suspensions = (new class extends Model {})->setTable('suspensions')->setConnection(ActiveStateResolverAdapterTest::replicated());

                return !$suspensions->newQuery()->where('identity_id', 1)->exists();
            }
        };

        self::assertTrue($identity->isActive(), 'The replica must lag the primary for this test to prove anything.');
        self::assertFalse($this->adapter()->isActive($identity));
    }

    /**
     * Once bound, MFA refuses a deactivated identity as `identity_inactive`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfaRefusesADeactivatedIdentityOnceBound(): void
    {
        $person = $this->createPerson();
        $caller = CallerContext::forIdentity($person, self::GUARD);

        $this->signInAndActOnSession($person);

        $person->forceFill(['is_active' => false])->save();

        self::assertTrue($person->isMfaActive());
        self::assertSame(FailureReason::IDENTITY_INACTIVE, Mfa::renameFactor($caller, 1, 'Phone')->reason);

        $person->forceFill(['is_active' => true])->save();

        self::assertSame(FailureReason::NOT_FOUND, Mfa::renameFactor($caller, 1, 'Phone')->reason);
    }

    /**
     * The name of the connection whose reads go to a lagging replica.
     *
     * @return string
     */
    public static function replicated(): string
    {
        return self::REPLICATED;
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver
     */
    #[\Override]
    protected function activeStateResolver(): ActiveStateResolver
    {
        return $this->adapter();
    }

    /**
     * An identity `laravel-authentication` holds active.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function activeIdentity(): MultiFactorAuthenticatable
    {
        return new Person;
    }

    /**
     * An identity `laravel-authentication` holds inactive.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function inactiveIdentity(): MultiFactorAuthenticatable
    {
        return (new Person)->forceFill(['is_active' => false]);
    }

    /**
     * Declare a connection whose reads go to an empty replica.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        Config::set('database.connections.' . self::REPLICATED, [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'read'     => ['database' => ':memory:'],
            'write'    => ['database' => ':memory:'],
        ]);
    }

    /**
     * A deactivatable identity with the given active states.
     *
     * @param  bool  $active
     * @param  bool  $mfaActive
     * @return \SineMacula\Laravel\Authentication\Contracts\CanBeActive&\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    private static function activatable(bool $active, bool $mfaActive): CanBeActive&MultiFactorAuthenticatable
    {
        $identity = new class extends User implements CanBeActive, MultiFactorAuthenticatable {
            use HasFactors;

            /** @var bool Whether `laravel-authentication` reads the identity as active. */
            public bool $active = true;

            /** @var bool Whether MFA's own reading takes the identity as active. */
            public bool $mfaActive = true;

            /**
             * Whether `laravel-authentication` reads the identity as active.
             *
             * @return bool
             */
            #[\Override]
            public function isActive(): bool
            {
                return $this->active;
            }

            /**
             * Whether MFA's own reading takes the identity as active.
             *
             * @return bool
             */
            #[\Override]
            public function isMfaActive(): bool
            {
                return $this->mfaActive;
            }
        };

        $identity->active    = $active;
        $identity->mfaActive = $mfaActive;

        return $identity;
    }

    /**
     * Resolve the adapter under test from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\ActiveStateResolverAdapter
     */
    private function adapter(): ActiveStateResolverAdapter
    {
        $adapter = $this->app?->make(ActiveStateResolverAdapter::class);

        self::assertInstanceOf(ActiveStateResolverAdapter::class, $adapter);

        return $adapter;
    }
}
