<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Storage\ConnectionAlignment;
use SineMacula\Laravel\Iam\Storage\StorageConnection;

/**
 * Checks every member key and identity model is on the shared connection, and
 * notes audit-log on another.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StorageCheck implements Check
{
    /** @var string The key naming the default connection. */
    private const string DEFAULT_KEY = 'database.default';

    /** @var string The key of audit-log's storage connection. */
    private const string AUDIT_KEY = 'audit-log.storage.connection';

    /** @var string The note for audit-log on another connection. */
    private const string AUDIT_ELSEWHERE = '`%s` names another connection than `%s`: audit-log\'s refusal of a read of the trail inside a change does not cover it.';

    /** @var string The key of the application's guards. */
    private const string GUARDS_KEY = 'auth.guards';

    /** @var string The key of the application's user providers. */
    private const string PROVIDERS_KEY = 'auth.providers';

    /** @var string The key of the user provider a guard naming none uses. */
    private const string DEFAULT_PROVIDER_KEY = 'auth.defaults.provider';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Storage\ConnectionAlignment  $alignment
     */
    public function __construct(

        /** The application whose members' providers are read. */
        private Application $app,

        /** The configuration the connections are read from. */
        private Repository $config,

        /** Reads and compares the member keys. */
        private ConnectionAlignment $alignment,
    ) {}

    /**
     * The subject the findings are reported under.
     *
     * @return string
     */
    #[\Override]
    public function subject(): string
    {
        return 'storage';
    }

    /**
     * The check always applies, since every member is required.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * Member keys aligned, the shared connection configured, identity models on
     * it, and audit-log noted.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [
            fn () => $this->alignment->assertAligned($this->config, $this->app),
            fn () => $this->assertConfigured(),
            ...array_map(fn (string $model): \Closure => fn () => $this->assertOnStorage($model), $this->identityModels()),
            fn (): ?string => $this->auditConnectionNote(),
        ];
    }

    /**
     * Refuse a shared connection `database.connections` does not configure.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertConfigured(): void
    {
        $storage = (new StorageConnection($this->config))->name();

        if ($storage !== null && !is_array($this->config->get('database.connections.' . $storage))) {
            throw new \InvalidArgumentException(sprintf('`%s` names a connection `database.connections` does not configure.', StorageConnection::KEY));
        }
    }

    /**
     * Refuse an identity model that is no Eloquent model or is on another
     * connection.
     *
     * @param  string  $model
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function assertOnStorage(string $model): void
    {
        if (!is_subclass_of($model, Model::class)) {
            throw new \InvalidArgumentException(sprintf('The identity model %s is no Eloquent model.', $model));
        }

        $storage = (new StorageConnection($this->config))->name();
        $default = $this->config->get(self::DEFAULT_KEY);

        if (((new $model)->getConnectionName() ?? $default) === ($storage ?? $default)) {
            return;
        }

        throw new \LogicException(sprintf('The identity model %s lives on another connection than `%s` names.', $model, StorageConnection::KEY));
    }

    /**
     * A note when audit-log stores the trail on another connection.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function auditConnectionNote(): ?string
    {
        $default = $this->config->get(self::DEFAULT_KEY);
        $audit   = $this->config->get(self::AUDIT_KEY);
        $storage = (new StorageConnection($this->config))->name();

        if ((is_string($audit) && $audit !== '' ? $audit : $default) === ($storage ?? $default)) {
            return null;
        }

        return sprintf(self::AUDIT_ELSEWHERE, self::AUDIT_KEY, StorageConnection::KEY);
    }

    /**
     * The models of the user providers `jwt` and `api_key` guards use, once
     * each.
     *
     * @return array<int, string>
     */
    private function identityModels(): array
    {
        $guards = $this->config->get(self::GUARDS_KEY);
        $models = [];

        foreach (is_array($guards) ? $guards : [] as $guard) {

            $model = $this->modelOfGuard($guard);

            if ($model === null) {
                continue;
            }

            $models[] = $model;
        }

        return array_unique($models);
    }

    /**
     * The model of the user provider the guard uses.
     *
     * @param  mixed  $guard
     * @return ?string
     */
    private function modelOfGuard(mixed $guard): ?string
    {
        $providers = $this->config->get(self::PROVIDERS_KEY);
        $default   = $this->config->get(self::DEFAULT_PROVIDER_KEY);

        return self::modelOf($guard, is_array($providers) ? $providers : [], is_string($default) ? $default : null);
    }

    /**
     * The model of a `jwt` or `api_key` guard's provider, or of the default
     * provider when it names none.
     *
     * @param  mixed  $guard
     * @param  array<array-key, mixed>  $providers
     * @param  ?string  $default
     * @return ?string
     */
    private static function modelOf(mixed $guard, array $providers, ?string $default): ?string
    {
        if (!is_array($guard) || !in_array($guard['driver'] ?? null, CaptureExclusions::DRIVERS, true)) {
            return null;
        }

        $named = $guard['provider'] ?? null;
        $name  = is_string($named) && $named !== '' ? $named : $default;

        if ($name === null) {
            return null;
        }

        $provider = $providers[$name]                        ?? null;
        $model    = is_array($provider) ? $provider['model'] ?? null : null;

        return is_string($model) && $model !== '' ? $model : null;
    }
}
