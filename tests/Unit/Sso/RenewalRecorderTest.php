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
 * Unit tests for the one renewal a re-authentication records: it is recorded
 * only while a redemption has opened the recorder, is taken back as recorded,
 * once, a second record while one is held is a `LogicException`, and opening or
 * closing the recorder leaves nothing held.
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
     * The renewal recorded is taken back as recorded, and is no longer held.
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
     * Recording a second renewal while one is held is a `LogicException`, and
     * the first is still the one held.
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
     * A renewal asked for while the recorder is closed, before any redemption
     * opened it or once one closed it, is one no redemption would write: it is
     * a `LogicException`, and nothing is held.
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
     * Opening the recorder forgets a renewal still held, and another may be
     * recorded.
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
     * Closing the recorder forgets a renewal still held, and refuses the next
     * until it is opened again.
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
     * A redemption's attempt that opens and closes the recorder while another
     * is still open leaves the other open: its renewal is still recorded, and
     * the recorder is closed once both have closed.
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
     * A close with no opening left changes nothing: the next opening opens the
     * recorder.
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
     * Assert the closed recorder refuses a renewal as one no redemption would
     * write, and holds nothing.
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
