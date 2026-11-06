<?php

declare(strict_types = 1);

namespace Tests\Unit\Sso\Translation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Sso\Translation\ClientTranslator;

/**
 * Unit tests for handing SSO the client `laravel-authentication` was handed:
 * its IP address and user agent cross as `laravel-authentication` keeps them,
 * and a client of which nothing is known stays one.
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
     * The IP address and user agent cross as given; the facts only a same-site
     * check judges stay behind.
     *
     * @return void
     */
    public function testTheAddressAndAgentCross(): void
    {
        $client = ClientTranslator::toSso(new ClientContext('192.0.2.10', 'iam-tests', 'https://app.iam.test', 'https://app.iam.test', ['origin']));

        self::assertSame('192.0.2.10', $client->ip);
        self::assertSame('iam-tests', $client->userAgent);
    }

    /**
     * A client of which nothing is known, as a job or a command hands over, is
     * one to SSO too.
     *
     * @return void
     */
    public function testAnUnknownClientStaysUnknown(): void
    {
        $client = ClientTranslator::toSso(new ClientContext(null, null));

        self::assertNull($client->ip);
        self::assertNull($client->userAgent);
    }
}
