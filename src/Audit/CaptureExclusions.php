<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Contracts\Config\Repository;

/**
 * What audit-log's own capture must leave alone so nothing the suite reports is
 * recorded twice (IAM-9.6, IAM-2.5): every guard of `laravel-authentication`'s
 * `jwt` and `api_key` drivers in `audit-log.capture.laravel.except_guards`, and
 * audit-log's Gate capture off.
 *
 * A `jwt` guard dispatches Laravel's `Login`, `Failed` and `Logout` beside
 * `laravel-authentication`'s own events, which this package maps; audit-log's
 * listener of Laravel's events would record each occurrence a second time
 * unless the guard is excluded. An `api_key` guard's `logout()` (and a trusted
 * `login()`) dispatches Laravel's event alone, with no event of the member's
 * beside it, since an API key has no session: there the exclusion IAM-9.6 asks
 * for prevents no double record, and removes audit-log's only record of it,
 * until `laravel-authentication` reports it with an event of its own. Not every
 * `Login` of a `jwt` guard has a mapped event beside it either: a sign-in
 * through the guard's own `attempt()` or `login()`, rather than
 * `laravel-authentication`'s session service, dispatches `Login` and a bind's
 * noise and no `SignedIn`, so on an excluded guard such a sign-in goes
 * unrecorded until `laravel-authentication` reports it with an event of its own
 * (a refused `attempt()` is still recorded, from its `AuthenticationFailed`).
 * The exclusion is kept regardless, since without it every sign-in through the
 * session service is recorded twice. `laravel-authorization` is always
 * installed with this package, and its decision events are the ones mapped
 * (`AuthorizationEventMapper`), the Gate checks it answers among them, so Gate
 * capture stays off.
 *
 * It only computes and answers: it never writes configuration. The application
 * sets the exclusions this answers and `iam:check` refuses a configuration that
 * does not hold them (decision Q5 (a)); at runtime audit-log reads its own keys
 * when each event arrives, and this package changes none of them. Every value
 * is read from configuration when it is asked for, never kept, so a guard
 * configured later counts.
 *
 * The guards are found by their driver, in the order `auth.guards` lists
 * them; a guard whose configuration is no array, or names no driver, is no
 * guard of either driver. The exclusions to write keep every name the
 * application already excludes, in its order, and add each guard still
 * missing; `['*']`, which excludes every guard, is kept as it is. An
 * `except_guards` value that is not a list of guard names is refused with an
 * `InvalidArgumentException` naming the key and never the value, as audit-log
 * refuses it, rather than replaced or read as excluding nothing. Gate capture
 * is off only while `audit-log.capture.gate.enabled` is `false`, or unset,
 * whose default is off: anything else, a value audit-log would refuse among
 * them, is not off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CaptureExclusions
{
    /** @var list<string> The drivers of `laravel-authentication`'s guards, whose Laravel events audit-log must not record. */
    public const array DRIVERS = ['jwt', 'api_key'];

    /** @var string The key of the guards audit-log's Laravel capture leaves alone. */
    public const string EXCEPT_GUARDS_KEY = 'audit-log.capture.laravel.except_guards';

    /** @var string The key turning audit-log's Gate capture on. */
    public const string GATE_KEY = 'audit-log.capture.gate.enabled';

    /** @var string The only member of `except_guards` that excludes every guard. */
    public const string ALL_GUARDS = '*';

    /** @var string The key of the application's guards. */
    private const string GUARDS_KEY = 'auth.guards';

    /** @var string Why an exclusion list that is no list of guard names is refused. */
    private const string MALFORMED = '`' . self::EXCEPT_GUARDS_KEY . '` must be a list of guard names, or [\'*\'].';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the guards and audit-log's capture settings are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * Every guard of the `jwt` or `api_key` driver, in the order the
     * application configures them.
     *
     * @return list<string>
     */
    public function guards(): array
    {
        $guards = $this->config->get(self::GUARDS_KEY);

        if (!is_array($guards)) {
            return [];
        }

        $names = [];

        foreach ($guards as $name => $guard) {

            if (!is_array($guard) || !in_array($guard['driver'] ?? null, self::DRIVERS, true)) {
                continue;
            }

            $names[] = (string) $name;
        }

        return $names;
    }

    /**
     * The guards that must be excluded and are not; none while every guard is
     * excluded.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function unexcludedGuards(): array
    {
        $excepted = $this->exceptedGuards();

        if ($excepted === [self::ALL_GUARDS]) {
            return [];
        }

        return array_values(array_diff($this->guards(), $excepted));
    }

    /**
     * The exclusions `except_guards` should hold: what it holds, then every
     * guard still missing, or `['*']` kept as it is.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function exceptGuards(): array
    {
        return [...$this->exceptedGuards(), ...$this->unexcludedGuards()];
    }

    /**
     * Whether audit-log's Gate capture is off.
     *
     * @return bool
     */
    public function isGateCaptureOff(): bool
    {
        return $this->config->get(self::GATE_KEY, false) === false;
    }

    /**
     * Whether the configuration holds both: every guard excluded and Gate
     * capture off.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function holds(): bool
    {
        return $this->unexcludedGuards() === [] && $this->isGateCaptureOff();
    }

    /**
     * The guards `except_guards` holds now: none when it is unset.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function exceptedGuards(): array
    {
        $excepted = $this->config->get(self::EXCEPT_GUARDS_KEY, []);

        if (!is_array($excepted) || !array_is_list($excepted)) {
            throw new \InvalidArgumentException(self::MALFORMED);
        }

        foreach ($excepted as $guard) {

            if (!is_string($guard) || $guard === '') {
                throw new \InvalidArgumentException(self::MALFORMED);
            }
        }

        if (in_array(self::ALL_GUARDS, $excepted, true) && $excepted !== [self::ALL_GUARDS]) {
            throw new \InvalidArgumentException(self::MALFORMED);
        }

        return $excepted;
    }
}
