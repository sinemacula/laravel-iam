<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Storage;

use Illuminate\Contracts\Config\Repository;

/**
 * The one storage connection every member keeps its tables on, and the member
 * keys that must name it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class StorageConnection
{
    /** @var string The key that names the shared storage connection. */
    public const string KEY = 'iam.storage.connection';

    /** @var list<string> The member keys that must name the shared connection. */
    public const array MEMBER_KEYS = [
        'authentication.storage.connection',
        'mfa.storage.connection',
        'sso.storage.connection',
        'authorization.connection',
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Read on every call. */
        private Repository $config,
    ) {}

    /**
     * The shared connection's name, or null for the default.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function name(): ?string
    {
        return self::read($this->config, self::KEY);
    }

    /**
     * Read a connection key: a name, or null (or empty) for the default.
     *
     * Anything else fails closed instead of falling back.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $key
     * @return ?string
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function read(Repository $config, string $key): ?string
    {
        $connection = $config->get($key);

        if ($connection !== null && !is_string($connection)) {
            throw new \InvalidArgumentException(sprintf('`%s` must be a connection name, or null or empty for the default connection.', $key));
        }

        return $connection === '' ? null : $connection;
    }
}
