<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Transactions;

use Illuminate\Contracts\Config\Repository;

/**
 * How many times a cross-member transaction is attempted, as
 * `iam.transactions.attempts` says.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RetrySettings
{
    /** @var string The key that holds the number of attempts. */
    public const string KEY = 'iam.transactions.attempts';

    /** @var int The number of attempts when the key is unset. */
    public const int DEFAULT_ATTEMPTS = 3;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the attempts are read from, on every call. */
        private Repository $config,
    ) {}

    /**
     * Return the number of attempts, the first run included: at least 1.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function attempts(): int
    {
        $attempts = $this->config->get(self::KEY);

        if ($attempts === null) {
            return self::DEFAULT_ATTEMPTS;
        }

        if (!is_int($attempts) || $attempts < 1) {

            $given = is_int($attempts) ? '[' . $attempts . ']' : get_debug_type($attempts);

            throw new \InvalidArgumentException(sprintf('`%s` must be a whole number of attempts of at least 1, the first included: %s given.', self::KEY, $given));
        }

        return $attempts;
    }
}
