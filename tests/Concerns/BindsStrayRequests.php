<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Http\Request;

/**
 * Binds a stray request in the container, carrying other values than the ones
 * an adapter is handed: another client's IP address and user agent, and, when
 * given, a body (another pending session's credential, say).
 *
 * An adapter's core method acts on the plain values the member hands it and
 * never on the current request, so a test binds one of these first and then
 * asserts that none of its values reached the answer: the handed caller,
 * client, pending credential and application are the ones used, whatever the
 * container holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait BindsStrayRequests
{
    /** @var string The IP address the stray request comes from. */
    protected const string STRAY_IP = '198.51.100.7';

    /** @var string The user agent the stray request sends. */
    protected const string STRAY_AGENT = 'stray-agent';

    /**
     * Bind a stray request in the container as the current request, from
     * another client than the tests', carrying the body given, and return it.
     *
     * @param  array<string, string>  $body
     * @return \Illuminate\Http\Request
     */
    protected function bindStrayRequest(array $body = []): Request
    {
        $app = $this->app;

        self::assertNotNull($app);

        $request = Request::create('/stray', 'POST', $body, server: ['REMOTE_ADDR' => self::STRAY_IP, 'HTTP_USER_AGENT' => self::STRAY_AGENT]);

        $app->instance('request', $request);

        self::assertSame($request, $app->make('request'));

        return $request;
    }
}
