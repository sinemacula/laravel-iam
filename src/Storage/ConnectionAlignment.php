<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Storage;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException;
use SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Keeps every member's storage connection on the shared one.
 *
 * A key is written only once its member has merged its configuration and
 * registered, since writing it into a published member config earlier would
 * replace the member's `storage` block. A key this package wrote follows the
 * shared connection if it changes. Connections are compared by the name they
 * resolve to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConnectionAlignment
{
    /** @var string The key that names the application's default connection. */
    private const string DEFAULT_KEY = 'database.default';

    /** @var array<string, class-string<\Illuminate\Support\ServiceProvider>> The provider that merges each member key's configuration. */
    private const array MEMBER_PROVIDERS = [
        'authentication.storage.connection' => AuthenticationServiceProvider::class,
        'mfa.storage.connection'            => MfaServiceProvider::class,
        'sso.storage.connection'            => SsoServiceProvider::class,
        'authorization.connection'          => AuthorizationServiceProvider::class,
    ];

    /**
     * Write the shared connection into unset or package-written member keys.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  array<string, ?string>  $written
     * @param  ?\Illuminate\Contracts\Foundation\Application  $app
     * @return array<string, ?string>
     *
     * @throws \InvalidArgumentException
     */
    public function align(Repository $config, array $written = [], ?Application $app = null): array
    {
        $storage = (new StorageConnection($config))->name();
        $writes  = [];

        foreach (self::MEMBER_PROVIDERS as $key => $provider) {

            if (self::isPending($config, $key, $provider, $app)) {
                continue;
            }

            $member = StorageConnection::read($config, $key);

            if ($member === $storage || ($member !== null && ($written[$key] ?? null) !== $member)) {
                continue;
            }

            $config->set($key, $storage);

            $writes[$key] = $storage;
        }

        return $writes;
    }

    /**
     * Refuse a member key that names another connection than the shared one.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  ?\Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException
     */
    public function assertAligned(Repository $config, ?Application $app = null): void
    {
        $storage = (new StorageConnection($config))->name();
        $default = $config->get(self::DEFAULT_KEY);

        foreach (self::MEMBER_PROVIDERS as $key => $provider) {

            if (self::isPending($config, $key, $provider, $app)) {
                continue;
            }

            self::assertSameConnection($key, StorageConnection::read($config, $key), $storage, $default);
        }
    }

    /**
     * Refuse a member whose service provider has not registered.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException
     */
    public function assertRegistered(Application $app): void
    {
        foreach (self::MEMBER_PROVIDERS as $key => $provider) {

            if ($app->getProviders($provider) === []) {
                throw MemberNotRegisteredException::forStorage($key, $provider);
            }
        }
    }

    /**
     * Refuse a key that resolves to another connection than the shared one.
     *
     * @param  string  $key
     * @param  ?string  $member
     * @param  ?string  $storage
     * @param  mixed  $default
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException
     */
    private static function assertSameConnection(string $key, ?string $member, ?string $storage, mixed $default): void
    {
        if (($member ?? $default) === ($storage ?? $default)) {
            return;
        }

        throw StorageConnectionMismatchException::forKey($key, $member, $storage);
    }

    /**
     * Whether the member key is left for later: unmerged or not yet registered.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $key
     * @param  class-string<\Illuminate\Support\ServiceProvider>  $provider
     * @param  ?\Illuminate\Contracts\Foundation\Application  $app
     * @return bool
     */
    private static function isPending(Repository $config, string $key, string $provider, ?Application $app): bool
    {
        return !self::isMerged($config, $key) || $app?->getProviders($provider) === [];
    }

    /**
     * Whether the key's member has merged its configuration.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $key
     * @return bool
     */
    private static function isMerged(Repository $config, string $key): bool
    {
        return $config->has(explode('.', $key)[0]);
    }
}
