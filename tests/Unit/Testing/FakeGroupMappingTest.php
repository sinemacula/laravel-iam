<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;
use SineMacula\Laravel\Iam\Testing\FakeGroupMapping;

/**
 * Unit tests for the fake group mapping.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeGroupMapping::class)]
final class FakeGroupMappingTest extends TestCase
{
    /** @var string The connection the groups are reported through. */
    private const string CONNECTION = 'connection-1';

    /** @var string The connection's tenant. */
    private const string TENANT = 'tenant-1';

    /**
     * Each group maps to its grants, each once, and every question is kept.
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
     * Once told to refuse, every question throws and is still kept.
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
     * `fake()` binds a fresh fake as the group mapping.
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
}
