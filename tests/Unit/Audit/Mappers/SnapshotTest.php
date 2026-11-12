<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit\Mappers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\Iam\Audit\Mappers\Enums\Attribution;
use SineMacula\Laravel\Iam\Audit\Mappers\Snapshot;

/**
 * Unit tests for how a snapshot's guard, session and client meet the
 * contributors'.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Snapshot::class)]
final class SnapshotTest extends TestCase
{
    /**
     * The event's guard, session and client beat the contributors'.
     *
     * @return void
     */
    public function testTheEventsPartsBeatTheContributors(): void
    {
        $snapshot = self::attributed(new Snapshot(null, null, null, 'api', 'session-1', '192.0.2.10', 'event-agent'));

        self::assertSame(['api', 'session-1', '192.0.2.10', 'event-agent'], [$snapshot->guard, $snapshot->sessionId, $snapshot->ip, $snapshot->userAgent]);
    }

    /**
     * Parts the event names none of are left to the contributors.
     *
     * @return void
     */
    public function testPartsTheEventLacksAreLeftToTheContributors(): void
    {
        $snapshot = self::attributed(new Snapshot(null, null, null, null, null, null, null));

        self::assertSame(['web', 'request-session', '198.51.100.1', 'request-agent'], [$snapshot->guard, $snapshot->sessionId, $snapshot->ip, $snapshot->userAgent]);
    }

    /**
     * Rows of `[ip, user agent]` naming one part of the client.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideHalfClients(): iterable
    {
        yield 'the IP alone' => ['192.0.2.10', null];

        yield 'the user agent alone' => [null, 'event-agent'];
    }

    /**
     * A client the event names half of takes nothing from the request.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @return void
     */
    #[DataProvider('provideHalfClients')]
    public function testAHalfClientTakesNothingFromTheRequest(?string $ip, ?string $userAgent): void
    {
        $snapshot = self::attributed(new Snapshot(null, null, null, null, null, $ip, $userAgent));

        self::assertSame([$ip, $userAgent], [$snapshot->ip, $snapshot->userAgent]);
    }

    /**
     * The record's snapshot once attributed and filled by a contributor.
     *
     * @param  \SineMacula\Laravel\Iam\Audit\Mappers\Snapshot  $snapshot
     * @return \SineMacula\Laravel\AuditLog\Records\PendingSnapshot
     */
    private static function attributed(Snapshot $snapshot): PendingSnapshot
    {
        $record = $snapshot->attribute(new PendingRecord, Attribution::CALLER, null);

        $record->fillGuard('web');
        $record->fillSession('request-session');
        $record->fillClient('198.51.100.1', 'request-agent');

        return $record->snapshot();
    }
}
