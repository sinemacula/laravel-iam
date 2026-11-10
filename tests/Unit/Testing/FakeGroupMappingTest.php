<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Illuminate\Container\Container;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;
use SineMacula\Laravel\Iam\Testing\FakeGroupMapping;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\GroupMappingTests;
use SineMacula\Laravel\Iam\Testing\Seams\GroupMappingContract;

/**
 * Proves the `GroupMapping` contract kit against this package's fake group
 * mapping (IAM-7.2): the fake maps each group to the grants it was told, any
 * other to nothing, each grant once, keeps every question, refuses once told
 * to, and binds itself as the application's mapping; and the kit's assertions
 * fail a mapping that answers no list, something that is no grant instruction,
 * different grants for the same groups, a grant for groups it does not map,
 * other grants than the groups give, or an answer for a question it declines.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeGroupMapping::class)]
#[CoversClass(GroupMappingContract::class)]
#[CoversTrait(GroupMappingTests::class)]
final class FakeGroupMappingTest extends TestCase
{
    use GroupMappingTests;

    /** @var string The connection the groups are reported through. */
    private const string CONNECTION = 'connection-1';

    /** @var string The connection's tenant. */
    private const string TENANT = 'tenant-1';

    /** @var bool Whether the mapping under test declines nothing. */
    private bool $declinesNothing = false;

    /**
     * Each group maps to the grants it was told, a role named by its name
     * holding in the tenant alone, each grant answered once in the order the
     * groups first name it, and every question is kept.
     *
     * @return void
     */
    public function testEachGroupMapsToWhatItWasToldOnce(): void
    {
        $fake = (new FakeGroupMapping)
            ->map('finance', 'invoices.viewer')
            ->map('finance-ops', 'invoices.viewer', GrantInstruction::roleWithSubtree('invoices.approver'));

        $grants = $fake->grantsFor(self::CONNECTION, self::TENANT, ['finance-ops', 'finance', 'engineering']);

        self::assertEquals([GrantInstruction::role('invoices.viewer'), GrantInstruction::roleWithSubtree('invoices.approver')], $grants);
        self::assertSame([['connection' => self::CONNECTION, 'tenant' => self::TENANT, 'groups' => ['finance-ops', 'finance', 'engineering']]], $fake->asked());
    }

    /**
     * Once told to refuse, every question throws what it was told, or its own
     * refusal, and is still kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryQuestionIsRefusedOnceToldTo(): void
    {
        $refusal = new \LogicException('Declined.');
        $fake    = (new FakeGroupMapping)->map('finance', 'invoices.viewer')->refuse($refusal);

        try {
            $fake->grantsFor(self::CONNECTION, self::TENANT, ['finance']);

            self::fail('The fake answered once told to refuse.');
        } catch (\LogicException $exception) {
            self::assertSame($refusal, $exception);
        }

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The fake group mapping refuses to map the groups.');

        try {
            (new FakeGroupMapping)->refuse()->grantsFor(self::CONNECTION, self::TENANT, []);
        } finally {
            self::assertCount(1, $fake->asked());
        }
    }

    /**
     * `fake()` binds a fresh fake as the application's group mapping in the
     * container given, or the application's own.
     *
     * @return void
     */
    public function testFakeBindsAFreshFakeAsTheMapping(): void
    {
        $container = new Container;
        $fake      = FakeGroupMapping::fake($container);

        self::assertSame($fake, $container->make(GroupMapping::class));
        self::assertNotSame($fake, FakeGroupMapping::fake($container));

        $previous = Container::getInstance();

        Container::setInstance($global = new Container);

        try {
            self::assertSame(FakeGroupMapping::fake(), $global->make(GroupMapping::class));
        } finally {
            Container::setInstance($previous);
        }
    }

    /**
     * Every check of the kit is a public test, so a test case using it runs
     * each one.
     *
     * @return void
     */
    public function testEveryCheckOfTheKitIsAPublicTest(): void
    {
        $methods = (new \ReflectionClass(GroupMappingTests::class))->getMethods();
        $checks  = array_values(array_filter($methods, static fn (\ReflectionMethod $method): bool => str_starts_with($method->getName(), 'test')));

        self::assertCount(5, $checks);

        foreach ($checks as $check) {
            self::assertTrue($check->isPublic(), sprintf('The kit\'s [%s] is not public.', $check->getName()));
        }
    }

    /**
     * The kit passes a mapping that declines nothing.
     *
     * @return void
     */
    public function testTheKitPassesAMappingThatDeclinesNothing(): void
    {
        $this->declinesNothing = true;

        $this->testGroupMappingRefusesByThrowing();
    }

    /**
     * The kit fails an answer that is no list.
     *
     * @return void
     */
    public function testTheKitFailsAnAnswerThatIsNoList(): void
    {
        $this->expectException(AssertionFailedError::class);

        GroupMappingContract::assertAnswersTheSameInstructions(static fn (): array => ['first' => GrantInstruction::role('invoices.viewer')]);
    }

    /**
     * The kit fails an answer holding something that is no grant instruction.
     *
     * @return void
     */
    public function testTheKitFailsAnAnswerThatIsNoInstruction(): void
    {
        $this->expectException(AssertionFailedError::class);

        GroupMappingContract::assertGrantsNothing(static fn (): array => ['invoices.viewer']);
    }

    /**
     * The kit fails a mapping that answers differently each time.
     *
     * @return void
     */
    public function testTheKitFailsAMappingThatAnswersDifferentlyEachTime(): void
    {
        $asked = 0;

        $this->expectException(AssertionFailedError::class);

        GroupMappingContract::assertAnswersTheSameInstructions(static function () use (&$asked): array {
            $asked++;

            return [GrantInstruction::role('role-' . $asked)];
        });
    }

    /**
     * The kit fails a mapping that grants something for groups it does not map.
     *
     * @return void
     */
    public function testTheKitFailsAGrantForUnmappedGroups(): void
    {
        $this->expectException(AssertionFailedError::class);

        GroupMappingContract::assertGrantsNothing(static fn (): array => [GrantInstruction::role('invoices.viewer')]);
    }

    /**
     * The kit fails a mapping that grants more than the groups give, or with
     * another reach.
     *
     * @return void
     */
    public function testTheKitFailsOtherGrantsThanTheGroupsGive(): void
    {
        $this->expectException(AssertionFailedError::class);

        GroupMappingContract::assertGrants(static fn (): array => [GrantInstruction::roleWithSubtree('invoices.viewer')], [GrantInstruction::role('invoices.viewer')]);
    }

    /**
     * The kit fails a mapping that answers a question it declines.
     *
     * @return void
     */
    public function testTheKitFailsAnAnswerForADeclinedQuestion(): void
    {
        $this->expectException(AssertionFailedError::class);

        GroupMappingContract::assertRefusesByThrowing(static fn (): array => []);
    }

    /**
     * The mapping under test.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\GroupMapping
     */
    #[\Override]
    protected function groupMapping(): GroupMapping
    {
        return (new FakeGroupMapping)
            ->map('finance', 'invoices.viewer')
            ->map('finance-ops', 'invoices.viewer', GrantInstruction::roleWithSubtree('invoices.approver'));
    }

    /**
     * The connection the groups are reported through.
     *
     * @return string
     */
    #[\Override]
    protected function connectionId(): string
    {
        return self::CONNECTION;
    }

    /**
     * The connection's tenant.
     *
     * @return string
     */
    #[\Override]
    protected function tenantId(): string
    {
        return self::TENANT;
    }

    /**
     * Groups the fake maps.
     *
     * @return list<string>
     */
    #[\Override]
    protected function mappedGroups(): array
    {
        return ['finance', 'finance-ops'];
    }

    /**
     * Groups the fake does not map.
     *
     * @return list<string>
     */
    #[\Override]
    protected function unmappedGroups(): array
    {
        return ['engineering', 'FINANCE'];
    }

    /**
     * The grants the mapped groups give.
     *
     * @return list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>
     */
    #[\Override]
    protected function expectedGrants(): array
    {
        return [GrantInstruction::role('invoices.viewer'), GrantInstruction::roleWithSubtree('invoices.approver')];
    }

    /**
     * A question the fake declines once told to refuse, or none.
     *
     * @return ?\Closure(): mixed
     */
    #[\Override]
    protected function declinedQuestion(): ?\Closure
    {
        if ($this->declinesNothing) {
            return null;
        }

        $fake = (new FakeGroupMapping)->refuse();

        return static fn (): array => $fake->grantsFor(self::CONNECTION, self::TENANT, ['finance']);
    }
}
