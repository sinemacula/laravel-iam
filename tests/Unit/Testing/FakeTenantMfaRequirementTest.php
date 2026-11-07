<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Illuminate\Container\Container;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRule;
use SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\TenantMfaRequirementTests;
use SineMacula\Laravel\Iam\Testing\Seams\TenantMfaRequirementContract;
use Tests\Fixtures\Resolvers\ClaimedTenant;

/**
 * Proves the `TenantMfaRequirement` contract kit against this package's fake
 * tenant MFA requirement (IAM-4.5): the fake answers a tenant the same way
 * while nothing changes, versions a changed answer anew, and throws for a
 * tenant it was told to fail for; and the kit's assertions fail a requirement
 * that breaks any of the three.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeTenantMfaRequirement::class)]
#[CoversClass(TenantMfaRequirementContract::class)]
#[CoversTrait(TenantMfaRequirementTests::class)]
final class FakeTenantMfaRequirementTest extends TestCase
{
    use TenantMfaRequirementTests;

    /** @var string The tenant the fake answers for. */
    private const string TENANT = 'tenant-1';

    /** @var string The tenant the fake is told to fail for. */
    private const string FAILING = 'tenant-unreadable';

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement The fake under test. */
    private ?FakeTenantMfaRequirement $fake = null;

    /**
     * A tenant the fake was never told about requires nothing, at a version of
     * its own, and the question is kept.
     *
     * @return void
     */
    public function testATenantNeverToldAboutRequiresNothing(): void
    {
        $rule = $this->fake()->requirementFor(new ClaimedTenant('tenant-2'), 'api');

        self::assertTrue($rule->isEmpty());
        self::assertNotNull($rule->version);
        self::assertNotSame($rule->version, $this->fake()->requirementFor(new ClaimedTenant('tenant-3'), 'api')->version);
        self::assertSame([['tenant' => 'tenant-2', 'application' => 'api'], ['tenant' => 'tenant-3', 'application' => 'api']], $this->fake()->asked());
    }

    /**
     * A tenant answers what it was last told to require, on every application,
     * at a version that names each change and fits what a session records.
     *
     * @return void
     */
    public function testATenantRequiresWhatItWasLastTold(): void
    {
        $fake  = $this->fake()->require(self::TENANT, self::multifactor());
        $first = $fake->requirementFor($this->tenantMfaTenant(), 'api');

        $fake->requireNothing(self::TENANT);

        $second = $fake->requirementFor($this->tenantMfaTenant(), 'admin');

        self::assertEquals(self::multifactor(), $first->requirement);
        self::assertTrue($second->isEmpty());
        self::assertNotSame($first->version, $second->version);
        self::assertLessThanOrEqual(TenantMfaRule::VERSION_MAX_LENGTH, mb_strlen((string) $second->version));
    }

    /**
     * The version names the tenant and counts the changes the test made to what
     * it requires: none before the first change, then one more with each, so a
     * tenant answers the same version across fakes while nothing changes.
     *
     * @return void
     */
    public function testTheVersionCountsTheChangesToTheTenantsRequirement(): void
    {
        $fake    = $this->fake();
        $version = static fn (int $changes): string => sprintf('fake:%s:%d', hash('xxh128', self::TENANT), $changes);

        self::assertSame($version(0), $fake->requirementFor($this->tenantMfaTenant(), 'api')->version);

        $fake->require(self::TENANT, self::multifactor());

        self::assertSame($version(1), $fake->requirementFor($this->tenantMfaTenant(), 'api')->version);

        $fake->requireNothing(self::TENANT);

        self::assertSame($version(2), $fake->requirementFor($this->tenantMfaTenant(), 'api')->version);
        self::assertSame($version(0), (new FakeTenantMfaRequirement)->requirementFor($this->tenantMfaTenant(), 'api')->version);
    }

    /**
     * A tenant the fake was told to fail for throws the failure given, until
     * the test changes what it requires.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailingTenantThrowsUntilItsRequirementChanges(): void
    {
        $failure = new \RuntimeException('Unreadable.');
        $fake    = $this->fake()->failFor(self::TENANT, $failure);

        try {
            $fake->requirementFor($this->tenantMfaTenant(), 'api');

            self::fail('The fake answered.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertTrue($fake->requireNothing(self::TENANT)->requirementFor($this->tenantMfaTenant(), 'api')->isEmpty());
    }

    /**
     * A tenant identified by what is neither a string nor an integer is
     * refused.
     *
     * @return void
     */
    public function testATenantOfNoIdentifierIsRefused(): void
    {
        $tenant = new class implements Tenant {
            /**
             * No identifier.
             *
             * @return mixed
             */
            #[\Override]
            public function getTenantIdentifier(): mixed
            {
                return null;
            }
        };

        $this->expectException(\InvalidArgumentException::class);

        $this->fake()->requirementFor($tenant, 'api');
    }

    /**
     * `fake()` binds a fresh fake as the application's requirement, in the
     * container given or the global one.
     *
     * @return void
     */
    public function testFakeBindsAFreshFakeAsTheRequirement(): void
    {
        $container = new Container;
        $fake      = FakeTenantMfaRequirement::fake($container);

        self::assertSame($fake, $container->make(TenantMfaRequirement::class));

        $previous = Container::getInstance();

        try {
            Container::setInstance($global = new Container);

            $other = FakeTenantMfaRequirement::fake();

            self::assertSame($other, $global->make(FakeTenantMfaRequirement::REQUIREMENT));
            self::assertNotSame($fake, $other);
        } finally {
            Container::setInstance($previous);
        }
    }

    /**
     * The kit fails a requirement that answers a tenant differently with
     * nothing changed.
     *
     * @return void
     */
    public function testTheKitFailsAnAnswerThatDrifts(): void
    {
        $answers = [new TenantMfaRule(self::multifactor(), '1'), new TenantMfaRule(self::multifactor(), '2')];

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('answered the same tenant at another version with nothing changed');

        TenantMfaRequirementContract::assertDeterministic(static function () use (&$answers): TenantMfaRule {
            return array_shift($answers) ?? self::fail('Asked too often.');
        });
    }

    /**
     * The kit fails a requirement that answers a tenant another requirement, at
     * the same version, with nothing changed.
     *
     * @return void
     */
    public function testTheKitFailsAnAnswerWhoseRequirementDrifts(): void
    {
        $answers = [new TenantMfaRule(self::multifactor(), '1'), TenantMfaRule::none('1')];

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('answered the same tenant differently with nothing changed');

        TenantMfaRequirementContract::assertDeterministic(static function () use (&$answers): TenantMfaRule {
            return array_shift($answers) ?? self::fail('Asked too often.');
        });
    }

    /**
     * The kit fails a requirement whose changed answer keeps its version.
     *
     * @return void
     */
    public function testTheKitFailsAChangedAnswerAtTheSameVersion(): void
    {
        $answers = [new TenantMfaRule(self::multifactor(), '1'), TenantMfaRule::none('1')];

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('answered a changed requirement at the version it answered before');

        TenantMfaRequirementContract::assertVersionChangesWithTheAnswer(
            static function () use (&$answers): TenantMfaRule {
                return array_shift($answers) ?? self::fail('Asked too often.');
            },
            static function (): void {},
        );
    }

    /**
     * The kit accepts a changed answer at no version, which is never taken as
     * already checked.
     *
     * @return void
     */
    public function testTheKitAcceptsAChangedAnswerAtNoVersion(): void
    {
        $answers = [new TenantMfaRule(self::multifactor(), '1'), new TenantMfaRule(new Requirement(additionalVerification: new RequirementPart))];

        TenantMfaRequirementContract::assertVersionChangesWithTheAnswer(
            static function () use (&$answers): TenantMfaRule {
                return array_shift($answers) ?? self::fail('Asked too often.');
            },
            static function (): void {},
        );
    }

    /**
     * The kit fails a change that changes nothing, so it never passes without
     * having seen a changed answer.
     *
     * @return void
     */
    public function testTheKitFailsAChangeThatChangesNothing(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('did not change what it answers');

        TenantMfaRequirementContract::assertVersionChangesWithTheAnswer(static fn (): TenantMfaRule => TenantMfaRule::none('1'), static function (): void {});
    }

    /**
     * The kit fails a requirement that answers for a tenant it cannot answer
     * for.
     *
     * @return void
     */
    public function testTheKitFailsAnAnswerForAnUnanswerableTenant(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('answered for a tenant it cannot answer for');

        TenantMfaRequirementContract::assertThrowsRatherThanAnswersNothing(static fn (): TenantMfaRule => TenantMfaRule::none());
    }

    /**
     * The fake under test.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement
     */
    #[\Override]
    protected function tenantMfaRequirement(): TenantMfaRequirement
    {
        return $this->fake()->require(self::TENANT, self::multifactor())->failFor(self::FAILING);
    }

    /**
     * The tenant the fake answers for.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    protected function tenantMfaTenant(): Tenant
    {
        return new ClaimedTenant(self::TENANT);
    }

    /**
     * The application asked about.
     *
     * @return string
     */
    #[\Override]
    protected function tenantMfaApplication(): string
    {
        return 'api';
    }

    /**
     * Change what the tenant requires: an additional verification on top.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return void
     */
    #[\Override]
    protected function changeTenantMfaRequirement(Tenant $tenant): void
    {
        self::assertSame(self::TENANT, $tenant->getTenantIdentifier());

        $this->fake()->require(self::TENANT, new Requirement(additionalVerification: new RequirementPart(60), multifactor: new RequirementPart(300)));
    }

    /**
     * The tenant the fake was told to fail for.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    protected function unanswerableTenant(): Tenant
    {
        return new ClaimedTenant(self::FAILING);
    }

    /**
     * The fake under test, made once per test.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement
     */
    private function fake(): FakeTenantMfaRequirement
    {
        return $this->fake ??= new FakeTenantMfaRequirement;
    }

    /**
     * Multifactor authentication within five minutes.
     *
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    private static function multifactor(): Requirement
    {
        return new Requirement(multifactor: new RequirementPart(300));
    }
}
