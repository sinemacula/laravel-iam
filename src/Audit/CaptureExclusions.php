<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Contracts\Config\Repository;

/**
 * What audit-log's own capture must leave alone so the mapped events are not
 * recorded twice: the `jwt` and `api_key` guards, and the Gate.
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

        /** The configuration, read on every call. */
        private Repository $config,
    ) {}

    /**
     * Every guard of the `jwt` or `api_key` driver, in configured order.
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
     * The guards that must be excluded and are not; none under `['*']`.
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
     * What `except_guards` should hold: its own guards, then each missing one.
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
     * Whether every guard is excluded and Gate capture is off.
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
     * The guards `except_guards` holds; a malformed value is refused.
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
