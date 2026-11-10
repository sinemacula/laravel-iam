<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use SineMacula\Laravel\Iam\Checks\Contracts\AuthenticationCheck;
use SineMacula\Laravel\Iam\Storage\ConnectionAlignment;
use SineMacula\Laravel\Iam\Storage\StorageConnection;

/**
 * The storage connections are one (IAM-2.3), at deploy.
 *
 * Boot already aligns and refuses a mismatch, but `iam:check` stands that
 * refusal aside so it can report it: every member whose storage key
 * `ConnectionAlignment` aligns (`laravel-authentication`, MFA and SSO) has
 * registered, every member key names the shared connection, and the shared
 * connection is one `database.connections` configures. The members without one
 * are left to their own reports: `laravel-audit-log`'s provider to
 * `AuditCheck`, and every member's to its check command, which `iam:check`
 * reports unregistered. The identity models live on the shared connection too:
 * the model of each user provider a `jwt` or `api_key` guard signs people in
 * through, read from the model's own connection without touching the database,
 * which boot cannot do. No setting names the principal models (an identity
 * reaches its principals through its own relation), so they are left to the
 * guide. A guard naming no provider signs people in through the default one
 * (`auth.defaults.provider`), as `laravel-authentication` and Laravel resolve
 * it, so that provider's model is read for it.
 *
 * `laravel-audit-log`'s storage connection is no member key this package
 * aligns, and the application may put the trail on a connection of its own;
 * one other than the shared connection is reported as a note, since audit-log's
 * refusal of a read of the trail inside a change (IAM-9.9) then does not cover
 * it.
 *
 * The identity model of a guard is `laravel-authentication`'s side, about that
 * guard, so `authentication:check` reports it too; the members' keys and the
 * shared connection are this package's, and stay with `iam:check`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StorageCheck implements AuthenticationCheck
{
    /** @var string The key naming the default connection. */
    private const string DEFAULT_KEY = 'database.default';

    /** @var string The key of audit-log's storage connection. */
    private const string AUDIT_KEY = 'audit-log.storage.connection';

    /** @var string The note of audit-log on another connection than the shared one. */
    private const string AUDIT_ELSEWHERE = '`%s` names another connection than `%s`: audit-log\'s refusal of a read of the trail inside a change does not cover it.';

    /** @var string The key of the application's guards. */
    private const string GUARDS_KEY = 'auth.guards';

    /** @var string The key of the application's user providers. */
    private const string PROVIDERS_KEY = 'auth.providers';

    /** @var string The key of the user provider a guard naming none signs people in through. */
    private const string DEFAULT_PROVIDER_KEY = 'auth.defaults.provider';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Storage\ConnectionAlignment  $alignment
     */
    public function __construct(

        /** The application whose members' registration is read. */
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
     * The check always applies: every member is required (IAM-1.3).
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * Every member with a storage key registered, every member key aligned, the
     * shared connection configured, every identity model on it, and audit-log's
     * connection noted when it is another.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [
            fn () => $this->alignment->assertRegistered($this->app),
            fn () => $this->alignment->assertAligned($this->config, $this->app),
            fn () => $this->assertConfigured(),
            ...array_map(fn (string $model): \Closure => fn () => $this->assertOnStorage($model), $this->identityModels()),
            fn (): ?string => $this->auditConnectionNote(),
        ];
    }

    /**
     * None: the members' keys and the shared connection are this package's.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function authenticationChecks(): array
    {
        return [];
    }

    /**
     * The identity model the guard signs people in through is on the shared
     * connection; none when it is no `jwt` or `api_key` guard, or names no
     * model.
     *
     * @param  string  $guard
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function guardChecks(string $guard): array
    {
        $model = $this->modelOfGuard($this->config->get(self::GUARDS_KEY . '.' . $guard));

        return $model === null ? [] : [fn () => $this->assertOnStorage($model)];
    }

    /**
     * Refuse a shared connection `database.connections` does not configure;
     * the default connection, named by leaving the key unset, always is.
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
     * Refuse an identity model that is no Eloquent model, or that lives on
     * another connection than the shared one.
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
     * A note when audit-log stores the trail on another connection than the
     * shared one.
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
     * The model of each user provider a `jwt` or `api_key` guard signs people
     * in through, once each, in the order the guards are configured.
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
     * The model of the user provider the guard's configuration signs people in
     * through, read from the configured providers.
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
     * The model of the user provider the guard signs people in through, when it
     * is a `jwt` or `api_key` guard: the provider it names, or the default one
     * when it names none, as `laravel-authentication` hands the guard's
     * provider to Laravel, which falls back to `auth.defaults.provider`.
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
