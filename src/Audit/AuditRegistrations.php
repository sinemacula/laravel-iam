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
 * Registers this package's part of the audit trail with `laravel-audit-log`
 * (IAM-9.1, IAM-9.2), from this package's `boot()`. Audit-log binds its
 * registries (the recorder, the event catalogue, the contributor and mapper
 * registries) as shared instances in its `register()`, takes registrations
 * until the application has booted, and freezes them from a `booted()` callback
 * its own `boot()` queues, which runs only once every provider has booted. So
 * once audit-log's provider has registered, this package registers at once, in
 * every provider order, its own boot before audit-log's included.
 *
 * When audit-log's provider has not registered yet (an application provider
 * registers it from its own `boot()`, or it is left out of discovery), its
 * registries are not bound, and a recorder resolved now would be a throwaway
 * whose registrations are lost: nothing is touched, and the registration is
 * queued for when the application has booted instead. That callback is queued
 * before audit-log's freeze, since audit-log queues its own only as it boots,
 * after this package's provider, so it runs while audit-log still takes
 * registrations. If audit-log has still not registered by then, the boot is
 * refused (`MemberNotRegisteredException`, naming audit-log's provider), as a
 * member this package aligns is, rather than leave an application that seems to
 * record the members' events and records none; except, as for those members,
 * while one of the console commands that list, describe, discover, cache or
 * clear configuration runs, which the provider says when it registers this
 * (`$refusesMissing` false): nothing is registered then, and the command runs,
 * so a stale package manifest or a provider left out of discovery can still be
 * inspected and cleared.
 *
 * While the mappers' switch is on (`iam.audit.mappers`), one mapper is mapped
 * for each member's marker interface (`AuthenticationEvent`, `MfaEvent`,
 * `SsoEvent`, `AuthorizationEvent`), so every event a member dispatches, and
 * only those, is described by its member's mapper (no member event implements
 * two of them, and audit-log never maps its own events), and every case of this
 * package's code enums is defined (`AuthenticationActivity`, `SessionActivity`,
 * `MfaActivity`, `SsoActivity`, `AuthorizationActivity`), none of which is a
 * code audit-log ships, so no code is ever defined twice. With it off nothing
 * is mapped or defined.
 *
 * The caller's context contributor (`CallerContextContributor`, IAM-9.7) is
 * registered whatever the switch says: it fills only the gaps of a record,
 * whoever describes it (a mapper of this package's or of the application's, or
 * the application's own record), from the caller a package guard already holds,
 * which audit-log's own actor contributor cannot read. It runs after
 * audit-log's own contributors and before any the application registers from a
 * later provider's `boot()`.
 *
 * A registration repeated identically changes nothing, so a provider booted
 * twice is harmless. Once the application has booted, audit-log refuses any
 * registration: a provider booted again then (forced) finds this package's part
 * already registered, which the application records (`REGISTERED`), and
 * registers nothing more; a provider whose first registration comes only then
 * is refused (`\LogicException`), failing its boot, rather than leave an
 * application that seems to record the members' events and records none.
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
     * Register the caller's context contributor while the application is still
     * booting, and the mappers and the codes they record while the mappers'
     * switch is on too, at once when audit-log's provider has registered and
     * once the application has booted when it has not; once it has booted,
     * nothing more when they are registered already, and a refusal when they
     * are not. An audit-log that has still not registered once the application
     * has booted refuses the boot only while `$refusesMissing` is true, which
     * the provider makes false while a configuration command runs.
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
     * Register this package's part once the application has booted, before
     * audit-log freezes its registries, for an audit-log whose provider had not
     * registered when this package's booted; refuse an audit-log that has still
     * not registered while `$refusesMissing` is true, and register nothing with
     * it while it is false.
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
     * Register the caller's context contributor with the application's
     * audit-log, and the mappers and the codes they record while the mappers'
     * switch is on, and record that this package's part is registered.
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
        $recorder = $app->make(Recorder::class);

        $recorder->contribute(CallerContextContributor::class);

        if ($app->make(AuditSettings::class)->mapsEvents()) {
            self::registerMappers($recorder);
        }

        $app->instance(self::REGISTERED, true);
    }

    /**
     * The refusal of a first registration once the application has booted, when
     * audit-log takes none, so no member event would be recorded.
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
     * Map each member's marker interface to its mapper, and define every code
     * of this package's enums.
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
