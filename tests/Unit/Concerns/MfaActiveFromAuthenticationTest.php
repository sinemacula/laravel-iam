<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Illuminate\Database\Capsule\Manager;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Iam\Concerns\MfaActiveFromAuthentication;

/**
 * Unit tests for MFA's active state read from `laravel-authentication`'s
 * (IAM-3.12): a model `laravel-authentication` can deactivate is active to MFA
 * exactly while it is active there, read from the primary as
 * `laravel-authentication` reads it, never from a lagging replica, and one with
 * no active state of its own there is active.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(MfaActiveFromAuthentication::class)]
final class MfaActiveFromAuthenticationTest extends TestCase
{
    /**
     * Return Eloquent to having no connection resolver, as the other unit tests
     * expect it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Model::unsetConnectionResolver();

        parent::tearDown();
    }

    /**
     * A model `laravel-authentication` can deactivate is active to MFA exactly
     * while it is active there.
     *
     * @return void
     */
    public function testAnIdentityIsActiveToMfaWhileAuthenticationReadsItActive(): void
    {
        foreach ([true, false] as $active) {

            $identity = new class ($active) implements CanBeActive {
                use MfaActiveFromAuthentication;

                /**
                 * Constructor.
                 *
                 * @param  bool  $active
                 */
                public function __construct(

                    /** Whether `laravel-authentication` reads the identity as active. */
                    private readonly bool $active,
                ) {}

                /**
                 * Whether `laravel-authentication` reads the identity as
                 * active.
                 *
                 * @return bool
                 */
                #[\Override]
                public function isActive(): bool
                {
                    return $this->active;
                }
            };

            self::assertSame($active, $identity->isMfaActive());
        }
    }

    /**
     * A model with no active state of `laravel-authentication`'s is active.
     *
     * @return void
     */
    public function testAnIdentityWithNoActiveStateIsActive(): void
    {
        $identity = new class {
            use MfaActiveFromAuthentication;
        };

        self::assertTrue($identity->isMfaActive());
    }

    /**
     * An identity whose active state reads the database is active to MFA as the
     * primary has it, as `laravel-authentication` reads it, not as a replica
     * that has not yet seen its suspension has it.
     *
     * @return void
     */
    public function testAnIdentityIsActiveToMfaAsThePrimaryHasIt(): void
    {
        $manager = new Manager;

        $manager->addConnection([
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'read'     => ['database' => ':memory:'],
            'write'    => ['database' => ':memory:'],
        ], 'replicated');

        $manager->bootEloquent();

        $connection = $manager->getConnection('replicated');

        foreach ([$connection->getPdo(), $connection->getReadPdo()] as $pdo) {
            $pdo->exec('create table suspensions (identity_id integer not null)');
        }

        $connection->getPdo()->exec('insert into suspensions (identity_id) values (1)');

        $suspensions = (new class extends Model {})->setTable('suspensions')->setConnection('replicated');

        $identity = new class ($suspensions) implements CanBeActive {
            use MfaActiveFromAuthentication;

            /**
             * Constructor.
             *
             * @param  \Illuminate\Database\Eloquent\Model  $suspensions
             */
            public function __construct(

                /** The model the identity's suspensions are read through. */
                private readonly Model $suspensions,
            ) {}

            /**
             * Whether the identity has no suspension, as its connection reads
             * it.
             *
             * @return bool
             */
            #[\Override]
            public function isActive(): bool
            {
                return !$this->suspensions->newQuery()->where('identity_id', 1)->exists();
            }
        };

        self::assertTrue($identity->isActive(), 'The replica must lag the primary for this test to prove anything.');
        self::assertFalse($identity->isMfaActive());
    }
}
