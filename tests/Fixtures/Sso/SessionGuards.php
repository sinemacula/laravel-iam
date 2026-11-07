<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;

/**
 * Resolves applications to guards of the `jwt` driver for a unit test, with no
 * application booted: each application named is a declared guard, answered by a
 * `JwtGuard` built without its dependencies, which nothing then asks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionGuards
{
    /**
     * Resolve each application to a guard of the `jwt` driver.
     *
     * @param  string  ...$applications
     * @return \SineMacula\Laravel\Iam\Mfa\CurrentSession
     *
     * @throws \ReflectionException
     */
    public static function resolving(string ...$applications): CurrentSession
    {
        $auth  = \Mockery::mock(AuthFactory::class);
        $guard = (new \ReflectionClass(JwtGuard::class))->newInstanceWithoutConstructor();

        $auth->allows('guard')->andReturn($guard);

        $guards = array_fill_keys($applications, ['driver' => 'jwt']);

        return new CurrentSession($auth, new Repository(['auth' => ['guards' => $guards]]), \Mockery::mock(ConnectionResolverInterface::class));
    }
}
