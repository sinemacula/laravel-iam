<?php

declare(strict_types = 1);

namespace Tests\Unit\Transactions;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Transactions\RetrySettings;

/**
 * Unit tests for reading how many times a cross-member transaction is attempted
 * from `iam.transactions.attempts`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RetrySettings::class)]
final class RetrySettingsTest extends TestCase
{
    /**
     * Unset, the work is attempted three times.
     *
     * @return void
     */
    public function testUnsetTheWorkIsAttemptedThreeTimes(): void
    {
        $settings = new RetrySettings(new Repository);

        self::assertSame(3, $settings->attempts());
        self::assertSame(RetrySettings::DEFAULT_ATTEMPTS, $settings->attempts());
    }

    /**
     * A whole number of at least one is the number of attempts, one included,
     * read again on every call.
     *
     * @return void
     */
    public function testAWholeNumberOfAtLeastOneIsTheNumberOfAttempts(): void
    {
        $config   = new Repository(['iam' => ['transactions' => ['attempts' => 1]]]);
        $settings = new RetrySettings($config);

        self::assertSame(1, $settings->attempts());

        $config->set(RetrySettings::KEY, 5);

        self::assertSame(5, $settings->attempts());
    }

    /**
     * Rows of `[configured value, message]` the attempts are refused for: fewer
     * than one attempt, and anything that is not a whole number.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideRefusedAttempts(): iterable
    {
        yield 'zero' => [0, '`iam.transactions.attempts` must be a whole number of attempts of at least 1, the first included: [0] given.'];

        yield 'negative' => [-1, '`iam.transactions.attempts` must be a whole number of attempts of at least 1, the first included: [-1] given.'];

        yield 'numeric string' => ['3', '`iam.transactions.attempts` must be a whole number of attempts of at least 1, the first included: string given.'];

        yield 'float' => [3.0, '`iam.transactions.attempts` must be a whole number of attempts of at least 1, the first included: float given.'];

        yield 'boolean' => [true, '`iam.transactions.attempts` must be a whole number of attempts of at least 1, the first included: bool given.'];
    }

    /**
     * Fewer than one attempt, or a value that is not a whole number, is
     * refused, naming the key and what it holds.
     *
     * @param  mixed  $attempts
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedAttempts')]
    public function testAnythingButAWholeNumberOfAtLeastOneIsRefused(mixed $attempts, string $message): void
    {
        $settings = new RetrySettings(new Repository(['iam' => ['transactions' => ['attempts' => $attempts]]]));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $settings->attempts();
    }
}
