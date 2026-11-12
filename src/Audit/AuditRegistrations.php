<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Application as FoundationApplication;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Iam\Audit\Enums\AuthenticationActivity;
use SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity;
use SineMacula\Laravel\Iam\Audit\Enums\MfaActivity;
use SineMacula\Laravel\Iam\Audit\Enums\SessionActivity;
use SineMacula\Laravel\Iam\Audit\Enums\SsoActivity;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthenticationEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthorizationEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\MfaEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\SsoEventMapper;
use SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * Registers the mappers and code definitions with `laravel-audit-log` before it
 * freezes its registries, waiting until boot when audit-log registers late.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuditRegistrations
{
    /** @var array<class-string, class-string<\SineMacula\Laravel\AuditLog\Contracts\EventMapper>> Each member's marker interface, and its mapper. */
    public const array MAPPERS = [
        AuthenticationEvent::class => AuthenticationEventMapper::class,
        MfaEvent::class            => MfaEventMapper::class,
        SsoEvent::class            => SsoEventMapper::class,
        AuthorizationEvent::class  => AuthorizationEventMapper::class,
    ];

    /** @var list<class-string<\SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents>> The enums defining every code the mappers record that audit-log does not ship. */
    public const array CODES = [
        AuthenticationActivity::class,
        SessionActivity::class,
        MfaActivity::class,
        SsoActivity::class,
        AuthorizationActivity::class,
    ];

    /** @var string The container key recording that this package's part is registered with the application's audit-log. */
    public const string REGISTERED = 'iam.audit.registered';

    /**
     * Register with audit-log, at once or once the application has booted.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  bool  $refusesMissing
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function register(Application $app, bool $refusesMissing): void
    {
        if ($app instanceof FoundationApplication && $app->isBooted()) {

            if (!$app->bound(self::REGISTERED)) {
                throw self::lateRegistration();
            }

            return;
        }

        if (!self::isAuditLogRegistered($app)) {

            $app->booted(static function (Application $app) use ($refusesMissing): void {
                self::registerOnceBooted($app, $refusesMissing);
            });

            return;
        }

        self::registerWith($app);
    }

    /**
     * Register once booted, refusing a still-missing audit-log unless a
     * configuration command runs.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  bool  $refusesMissing
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException
     */
    private static function registerOnceBooted(Application $app, bool $refusesMissing): void
    {
        if (!$refusesMissing && !self::isAuditLogRegistered($app)) {
            return;
        }

        self::assertAuditLogRegistered($app);
        self::registerWith($app);
    }

    /**
     * Refuse an application whose audit-log has still not registered.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException
     */
    private static function assertAuditLogRegistered(Application $app): void
    {
        if (!self::isAuditLogRegistered($app)) {
            throw MemberNotRegisteredException::forAuditTrail(self::REGISTERED, AuditLogServiceProvider::class);
        }
    }

    /**
     * Whether audit-log's provider has registered with the application.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return bool
     */
    private static function isAuditLogRegistered(Application $app): bool
    {
        return $app->getProviders(AuditLogServiceProvider::class) !== [];
    }

    /**
     * Register the mappers and their codes while switched on, and record it.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function registerWith(Application $app): void
    {
        if ($app->make(AuditSettings::class)->mapsEvents()) {
            self::registerMappers($app->make(Recorder::class));
        }

        $app->instance(self::REGISTERED, true);
    }

    /**
     * The refusal of a first registration once audit-log takes none.
     *
     * @return \LogicException
     */
    private static function lateRegistration(): \LogicException
    {
        return new \LogicException(
            'laravel-iam was registered after the application booted, when laravel-audit-log takes no registration, '
            . 'so no member event would be recorded; register its provider before the application boots.',
        );
    }

    /**
     * Define every code and map each member's marker interface to its mapper.
     *
     * @param  \SineMacula\Laravel\AuditLog\Recorder  $recorder
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function registerMappers(Recorder $recorder): void
    {
        foreach (self::CODES as $codes) {
            $recorder->define($codes);
        }

        foreach (self::MAPPERS as $marker => $mapper) {
            $recorder->map($marker, $mapper);
        }
    }
}
