<?php

declare(strict_types = 1);

namespace Tests\Unit\Mfa\Translation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\ClientContext as AuthenticationClient;
use SineMacula\Laravel\Iam\Mfa\Translation\ClientTranslator;
use SineMacula\Laravel\Mfa\Context\ClientContext as MfaClient;

/**
 * Unit tests for translating the client an action is served to between MFA's
 * client context and `laravel-authentication`'s, either way.
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
     * MFA's client crosses one to one: its IP address, user agent, `Origin`,
     * scheme and host, and the names of the headers it carried with a value.
     *
     * @return void
     */
    public function testMfasClientCrossesWithEveryFact(): void
    {
        $mfa    = new MfaClient('192.0.2.10', 'iam-tests', 'https://app.example.test', 'https://api.example.test', ['X-Requested-With', 'Content_Type']);
        $client = ClientTranslator::toAuthentication($mfa);

        self::assertSame('192.0.2.10', $client->ip);
        self::assertSame('iam-tests', $client->userAgent);
        self::assertSame('https://app.example.test', $client->origin);
        self::assertSame('https://api.example.test', $client->schemeAndHost);
        self::assertSame(['x-requested-with', 'content-type'], $client->nonEmptyHeaders);
        self::assertTrue($client->carriesHeader('X-Requested-With'));
    }

    /**
     * A client with no same-site facts crosses with none: nothing MFA does not
     * carry is invented.
     *
     * @return void
     */
    public function testAClientWithoutSameSiteFactsCrossesWithNone(): void
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
     * `laravel-authentication`'s client crosses to MFA's one to one: its IP
     * address, user agent, `Origin`, scheme and host, and the names of the
     * headers it carried with a value.
     *
     * @return void
     */
    public function testLaravelAuthenticationsClientCrossesToMfaWithEveryFact(): void
    {
        $authentication = new AuthenticationClient('192.0.2.10', 'iam-tests', 'https://app.example.test', 'https://api.example.test', ['X-Requested-With', 'Content_Type']);
        $client         = ClientTranslator::toMfa($authentication);

        self::assertSame('192.0.2.10', $client->ip);
        self::assertSame('iam-tests', $client->userAgent);
        self::assertSame('https://app.example.test', $client->origin);
        self::assertSame('https://api.example.test', $client->schemeAndHost);
        self::assertSame(['x-requested-with', 'content-type'], $client->nonEmptyHeaders);
        self::assertTrue($client->carriesHeader('X-Requested-With'));
    }

    /**
     * `laravel-authentication`'s client with no same-site facts crosses to MFA
     * with none, its IP address and user agent as it kept them.
     *
     * @return void
     */
    public function testLaravelAuthenticationsClientWithoutSameSiteFactsCrossesToMfaWithNone(): void
    {
        $client = ClientTranslator::toMfa(new AuthenticationClient('not-an-address', 'iam-tests'));

        self::assertNull($client->ip);
        self::assertSame('iam-tests', $client->userAgent);
        self::assertNull($client->origin);
        self::assertNull($client->schemeAndHost);
        self::assertSame([], $client->nonEmptyHeaders);
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
