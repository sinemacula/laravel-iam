<?php

declare(strict_types = 1);

namespace Tests\Unit\Sso;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Sso\LinkCallers;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Unit tests for the callers handed in for SSO's freshness in this request:
 * none is named until one is opened, the latest open answers, closing it leaves
 * the one opened before it, and a close with none open changes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkCallers::class)]
final class LinkCallersTest extends TestCase
{
    /**
     * No caller is named until a redemption opens the record.
     *
     * @return void
     */
    public function testNoCallerIsNamedBeforeARedemptionOpens(): void
    {
        self::assertNull((new LinkCallers)->current());
    }

    /**
     * The latest caller opened is named with its application and whether a
     * transaction was open when it was handed in; closing it names the one
     * opened before it, and closing that names none.
     *
     * @return void
     */
    public function testTheLatestRedemptionOpenNamesItsCaller(): void
    {
        $callers = new LinkCallers;
        $first   = new IdentityReference('person', '1');
        $second  = new IdentityReference('person', '2');

        $callers->open('api', $first, false);

        self::assertSame(['application' => 'api', 'caller' => $first, 'inTransaction' => false], $callers->current());

        $callers->open('admin', $second, true);

        self::assertSame(['application' => 'admin', 'caller' => $second, 'inTransaction' => true], $callers->current());

        $callers->close();

        self::assertSame(['application' => 'api', 'caller' => $first, 'inTransaction' => false], $callers->current());

        $callers->close();

        self::assertNull($callers->current());
    }

    /**
     * A close with no redemption open changes nothing: the next one opened is
     * named, and closing it names none.
     *
     * @return void
     */
    public function testACloseWithNoneOpenChangesNothing(): void
    {
        $callers = new LinkCallers;
        $caller  = new IdentityReference('person', '1');

        $callers->close();
        $callers->open('api', $caller, false);

        self::assertSame(['application' => 'api', 'caller' => $caller, 'inTransaction' => false], $callers->current());

        $callers->close();

        self::assertNull($callers->current());
    }
}
