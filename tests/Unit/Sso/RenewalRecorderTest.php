<?php

declare(strict_types = 1);

namespace Tests\Unit\Sso;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Sso\Renewal;
use SineMacula\Laravel\Iam\Sso\RenewalRecorder;
use Tests\Fixtures\Sso\Redemptions;

/**
 * Unit tests for the recorder of a re-authentication's one renewal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RenewalRecorder::class)]
#[CoversClass(Renewal::class)]
final class RenewalRecorderTest extends TestCase
{
    /** @var string What a renewal asked for while no redemption is open to write it is. */
    private const string NO_REDEMPTION = 'SSO asked for a renewal no redemption would write: a re-authentication is redeemed through Iam::reauthentications().';

    /**
     * The renewal is taken back as recorded, and is no longer held.
     *
     * @return void
     */
    public function testTheRenewalIsTakenBackOnce(): void
    {
        $recorder = new RenewalRecorder;
        $identity = Redemptions::identity();
        $time     = CarbonImmutable::parse(Redemptions::AUTHENTICATED_AT);
        $evidence = Redemptions::evidence();

        $recorder->open();

        self::assertFalse($recorder->isHolding());

        $recorder->record($identity, Redemptions::SESSION, $time, $evidence);

        self::assertTrue($recorder->isHolding());

        $renewal = $recorder->take();

        self::assertNotNull($renewal);
        self::assertSame($identity, $renewal->identity);
        self::assertSame(Redemptions::SESSION, $renewal->sessionId);
        self::assertSame($time, $renewal->authenticatedAt);
        self::assertSame($evidence, $renewal->evidence);
        self::assertFalse($recorder->isHolding());
        self::assertNull($recorder->take());
    }

    /**
     * A renewal recorded with no evidence is held with none.
     *
     * @return void
     */
    public function testARenewalMayHoldNoEvidence(): void
    {
        $recorder = new RenewalRecorder;

        $recorder->open();
        $recorder->record(Redemptions::identity(), Redemptions::SESSION, CarbonImmutable::parse(Redemptions::AUTHENTICATED_AT), null);

        self::assertNull($recorder->take()?->evidence);
    }

    /**
     * A second renewal while one is held is a `LogicException`.
     *
     * @return void
     */
    public function testASecondRenewalIsALogicException(): void
    {
        $recorder = new RenewalRecorder;
        $time     = CarbonImmutable::parse(Redemptions::AUTHENTICATED_AT);

        $recorder->open();
        $recorder->record(Redemptions::identity(), Redemptions::SESSION, $time, null);

        try {
            $recorder->record(Redemptions::identity(), 'session-2', $time, null);

            self::fail('A second renewal was recorded.');
        } catch (\LogicException $exception) {
            self::assertSame('A re-authentication renews its session once: a second renewal was recorded in one redemption.', $exception->getMessage());
        }

        self::assertSame(Redemptions::SESSION, $recorder->take()?->sessionId);
    }

    /**
     * A renewal taken leaves room for the next redemption's.
     *
     * @return void
     */
    public function testARenewalTakenLeavesRoomForTheNext(): void
    {
        $recorder = new RenewalRecorder;
        $time     = CarbonImmutable::parse(Redemptions::AUTHENTICATED_AT);

        $recorder->open();
        $recorder->record(Redemptions::identity(), Redemptions::SESSION, $time, null);
        $recorder->take();
        $recorder->record(Redemptions::identity(), 'session-2', $time, null);

        self::assertSame('session-2', $recorder->take()?->sessionId);
    }

    /**
     * A renewal while the recorder is closed is a `LogicException`, and nothing
     * is held.
     *
     * @return void
     */
    public function testARenewalWhileClosedIsALogicException(): void
    {
        $recorder = new RenewalRecorder;

        self::assertRefusedWhileClosed($recorder);

        $recorder->open();
        $recorder->close();

        self::assertRefusedWhileClosed($recorder);
    }

    /**
     * Opening the recorder forgets a renewal still held.
     *
     * @return void
     */
    public function testOpeningForgetsARenewalHeld(): void
    {
        $recorder = new RenewalRecorder;
        $time     = CarbonImmutable::parse(Redemptions::AUTHENTICATED_AT);

        $recorder->open();
        $recorder->record(Redemptions::identity(), Redemptions::SESSION, $time, null);
        $recorder->open();

        self::assertFalse($recorder->isHolding());

        $recorder->record(Redemptions::identity(), 'session-2', $time, null);

        self::assertSame('session-2', $recorder->take()?->sessionId);
    }

    /**
     * Closing the recorder forgets a renewal and refuses the next until
     * reopened.
     *
     * @return void
     */
    public function testClosingForgetsARenewalHeld(): void
    {
        $recorder = new RenewalRecorder;
        $time     = CarbonImmutable::parse(Redemptions::AUTHENTICATED_AT);

        $recorder->open();
        $recorder->record(Redemptions::identity(), Redemptions::SESSION, $time, null);
        $recorder->close();

        self::assertFalse($recorder->isHolding());
        self::assertNull($recorder->take());

        $recorder->open();
        $recorder->record(Redemptions::identity(), 'session-2', $time, null);

        self::assertSame('session-2', $recorder->take()?->sessionId);
    }

    /**
     * A nested opening and closing leaves the outer redemption open.
     *
     * @return void
     */
    public function testANestedOpeningLeavesTheOuterOpen(): void
    {
        $recorder = new RenewalRecorder;
        $time     = CarbonImmutable::parse(Redemptions::AUTHENTICATED_AT);

        $recorder->open();
        $recorder->open();
        $recorder->close();
        $recorder->record(Redemptions::identity(), Redemptions::SESSION, $time, null);

        self::assertSame(Redemptions::SESSION, $recorder->take()?->sessionId);

        $recorder->close();

        self::assertRefusedWhileClosed($recorder);
    }

    /**
     * A close with no opening left changes nothing.
     *
     * @return void
     */
    public function testACloseWithNoOpeningLeftChangesNothing(): void
    {
        $recorder = new RenewalRecorder;

        $recorder->close();
        $recorder->open();
        $recorder->record(Redemptions::identity(), Redemptions::SESSION, CarbonImmutable::parse(Redemptions::AUTHENTICATED_AT), null);

        self::assertSame(Redemptions::SESSION, $recorder->take()?->sessionId);
    }

    /**
     * Assert the closed recorder refuses a renewal and holds nothing.
     *
     * @param  \SineMacula\Laravel\Iam\Sso\RenewalRecorder  $recorder
     * @return void
     */
    private static function assertRefusedWhileClosed(RenewalRecorder $recorder): void
    {
        try {
            $recorder->record(Redemptions::identity(), Redemptions::SESSION, CarbonImmutable::parse(Redemptions::AUTHENTICATED_AT), null);

            self::fail('A renewal was recorded while the recorder was closed.');
        } catch (\LogicException $exception) {
            self::assertSame(self::NO_REDEMPTION, $exception->getMessage());
        }

        self::assertFalse($recorder->isHolding());
    }
}
