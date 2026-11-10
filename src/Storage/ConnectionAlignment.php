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
 * Keeps every member's storage connection on the one this package configures
 * (IAM-2.3).
 *
 * Members read their connection lazily, so aligning their keys before the
 * application boots is enough. A member key left unset is given the shared
 * connection; a member key naming another connection refuses boot, since a
 * change that spans members could not then run in one transaction, and so does
 * a member whose service provider has not registered once the application has
 * booted, since its key could never be aligned.
 *
 * `laravel-authorization`'s key is `authorization.connection`, which it reads
 * on every query, migration and transaction of its own
 * (`AuthorizationConnection`), so its grants commit or roll back with a change
 * that spans members (a provisioned membership, a grant that widens a person's
 * scope through SSO's scope widening) and its grant scope query reads the
 * tenant tree on the connection the tree is on.
 *
 * A key is written only once its member has merged its configuration, and, when
 * the application is given, only once its member's provider has registered: an
 * application's published member configuration can be present before then, and
 * a key written into it would replace the member's whole `storage` block, or
 * mask `laravel-authorization`'s own key, the member's own value from its
 * environment included, when the member merges its configuration. A key a
 * previous call wrote, and that still holds what it wrote, is the package's
 * rather than the application's, so it follows the shared connection if that
 * has changed since.
 *
 * With `iam.storage.connection` unset, the shared connection is the default
 * one, and so is every member's whose key is unset: nothing is written, and a
 * member key is refused only when it names a connection other than the default.
 * Connections are compared by the name they resolve to, so a key that names the
 * default connection agrees with one left unset.
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

    /** @var array<string, class-string<\Illuminate\Support\ServiceProvider>> The service provider that merges each member key's configuration. */
    private const array MEMBER_PROVIDERS = [
        'authentication.storage.connection' => AuthenticationServiceProvider::class,
        'mfa.storage.connection'            => MfaServiceProvider::class,
        'sso.storage.connection'            => SsoServiceProvider::class,
        'authorization.connection'          => AuthorizationServiceProvider::class,
    ];

    /**
     * Write the shared connection into every member key that is unset, or still
     * holds what an earlier call wrote into it, leaving every other key of the
     * member's configuration as it is, and return what this call wrote.
     *
     * A member whose configuration is not yet merged, or, when the application
     * is given, whose service provider has not registered yet, is left for a
     * later call, so the member's own value, from its environment, is never
     * masked.
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
     * Refuse a member key that names a connection other than the shared one.
     *
     * A member whose configuration is not merged, or, when the application is
     * given, whose service provider has not registered yet, is left for a later
     * call, as `align()` leaves it: a key read before the member has merged its
     * configuration is not the one the member will read.
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
     * Refuse a member whose service provider has not registered, naming the
     * first: its key could never be aligned, nor checked.
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
     * Refuse a member key whose connection, resolved against the default one,
     * is not the shared connection.
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
     * Tell whether a member key is left for a later call: its member has not
     * merged its configuration, or, when the application is given, its service
     * provider has not registered yet.
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
     * Tell whether the member a key belongs to has merged its configuration; a
     * member that has not registered yet has nothing to align.
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
