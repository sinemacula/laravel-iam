<?php

declare(strict_types = 1);

namespace Tests\Unit\Mfa\Translation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Mfa\Translation\ClientTranslator;
use SineMacula\Laravel\Mfa\Context\ClientContext as MfaClient;

/**
 * Unit tests for translating the client an action is served to from MFA's
 * client context into `laravel-authentication`'s.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClientTranslator::class)]
final class ClientTranslatorTest extends TestCase
{
    /**
     * MFA's client crosses with its IP address and user agent, and with none of
     * the facts a same-site check judges.
     *
     * @return void
     */
    public function testMfasClientCrossesWithItsAddressAndAgentAlone(): void
    {
        $client = ClientTranslator::toAuthentication(new MfaClient('192.0.2.10', 'iam-tests'));

        self::assertSame('192.0.2.10', $client->ip);
        self::assertSame('iam-tests', $client->userAgent);
        self::assertNull($client->origin);
        self::assertNull($client->schemeAndHost);
        self::assertSame([], $client->nonEmptyHeaders);
    }

    /**
     * `laravel-authentication` keeps what it stores safely: an IP address that
     * is not one is dropped.
     *
     * @return void
     */
    public function testAnAddressThatIsNoneIsDropped(): void
    {
        $client = ClientTranslator::toAuthentication(new MfaClient('not-an-address', 'iam-tests'));

        self::assertNull($client->ip);
        self::assertSame('iam-tests', $client->userAgent);
    }

    /**
     * A client MFA hands no client for is one of which nothing is known.
     *
     * @return void
     */
    public function testAnUnknownClientKnowsNothing(): void
    {
        $client = ClientTranslator::unknown();

        self::assertNull($client->ip);
        self::assertNull($client->userAgent);
        self::assertNull($client->origin);
        self::assertNull($client->schemeAndHost);
        self::assertSame([], $client->nonEmptyHeaders);
    }
}
