<?php

declare(strict_types = 1);

namespace Tests\Unit\Sso\Translation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Sso\Translation\ClientTranslator;

/**
 * Unit tests for translating `laravel-authentication`'s client into SSO's.
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
     * The IP address and user agent cross as given.
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
     * A client of which nothing is known stays one.
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
