<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Mfa\ChallengeGatewayAdapter;
use SineMacula\Laravel\Iam\Mfa\FactorCodeCountersAdapter;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Codes\Concerns\ArrangesDeliveredFactors;
use Tests\Fixtures\Mfa\Codes\Concerns\DeliversFactorCodes;
use Tests\TestCase;

/**
 * Integration tests for the order a delivered factor's code challenge takes its
 * locks in, once MFA's challenge gateway is `laravel-authentication`'s factor
 * codes (IAM-3.9): MFA's identity state, then its factors, then the session
 * whose first factor MFA's counters read, then `laravel-authentication`'s
 * counts on code requests or checks, which it takes inside MFA's transaction
 * when MFA calls from inside one, then its challenge, last, whether the code is
 * sent or checked, at both isolation levels. Every path that challenges a
 * factor takes the identity's state first, so two of them never wait on each
 * other in the other order, and `laravel-authentication` takes its counts in
 * one order of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeGatewayAdapter::class)]
#[CoversClass(FactorCodeCountersAdapter::class)]
final class CodeChallengeLockOrderTest extends TestCase
{
    use ArrangesDeliveredFactors, DeliversFactorCodes, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var list<string> The tables a challenge locks or writes, in the order it must first do so. */
    private const array ORDER = ['mfa_identity_states', 'mfa_factors', 'authentication_sessions', 'rate_limits', 'one_time_codes'];

    /** @var list<string> The statements made on the storage connection while recording. */
    private array $statements = [];

    /** @var bool Whether the storage connection's statements are being recorded. */
    private bool $recording = false;

    /**
     * Fake the delivery of factor codes, and record the storage connection's
     * statements while asked to.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fakeFactorCodeDelivery();

        $storage = self::storage()->getName();

        DB::listen(function (QueryExecuted $query) use ($storage): void {

            if (!$this->recording || $query->connectionName !== $storage) {
                return;
            }

            $this->statements[] = preg_replace('/\s+/', ' ', $query->sql) ?? $query->sql;
        });
    }

    /**
     * Rows of `[what is done, isolation level]`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideChallengesAtIsolationLevels(): iterable
    {
        foreach (['a send', 'a check'] as $challenge) {
            foreach (self::provideIsolationLevels() as $name => [$level]) {
                yield $challenge . ' at ' . $name => [$challenge, $level];
            }
        }
    }

    /**
     * A step-up's code, sent or checked through MFA, takes the identity's
     * state, its factors, the session, `laravel-authentication`'s counts and
     * the challenge, in that order, and the challenge only once all the others
     * are held.
     *
     * @param  string  $challenge
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChallengesAtIsolationLevels')]
    public function testAChallengeLocksTheIdentityTheFactorsTheSessionTheCountsThenTheChallenge(string $challenge, string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $factor = $this->deliveredFactor($person);

        if ($challenge === 'a send') {
            $this->record(static fn (): bool => Mfa::sendCode($factor->id, Purpose::STEP_UP)->wasSent());
        } else {
            $sent = Mfa::sendCode($factor->id, Purpose::STEP_UP);
            $code = $this->deliveredCodeTo(self::DELIVERED_PHONE);

            $this->record(static fn (): bool => Mfa::verify(Submission::challenge($factor->id, (string) $sent->challengeId, $code), Purpose::STEP_UP)->isVerified());
        }

        $listing = implode("\n", $this->statements);
        $first   = array_map(fn (string $table): ?int => $this->firstLockOf($table), self::ORDER);

        foreach ($first as $index => $position) {
            self::assertIsInt($position, sprintf("Nothing locked or wrote [%s]:\n%s", self::ORDER[$index], $listing));
        }

        $sorted = $first;

        sort($sorted);

        self::assertSame($sorted, $first, $listing);
        self::assertSame(self::ORDER[0], self::tableOf($this->statements[$this->firstLockOfAny()] ?? ''), $listing);
    }

    /**
     * Bind the application's gateways before the application boots.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $this->defineFactorCodes($app);
    }

    /**
     * Run the challenge, failing unless it went ahead, recording the statements
     * it made on the storage connection.
     *
     * @param  \Closure(): bool  $challenge
     * @return void
     */
    private function record(\Closure $challenge): void
    {
        $this->statements = [];
        $this->recording  = true;

        try {
            self::assertTrue($challenge(), 'The challenge did not go ahead.');
        } finally {
            $this->recording = false;
        }
    }

    /**
     * The index of the first statement that locks or writes a row of the table,
     * or `null` when none does.
     *
     * @param  string  $table
     * @return ?int
     */
    private function firstLockOf(string $table): ?int
    {
        foreach ($this->statements as $index => $sql) {
            if (self::isLock($sql) && self::tableOf($sql) === $table) {
                return $index;
            }
        }

        return null;
    }

    /**
     * The index of the first statement that locks or writes a row of any of the
     * tables a challenge locks.
     *
     * @return ?int
     */
    private function firstLockOfAny(): ?int
    {
        foreach ($this->statements as $index => $sql) {
            if (self::isLock($sql) && in_array(self::tableOf($sql), self::ORDER, true)) {
                return $index;
            }
        }

        return null;
    }

    /**
     * Whether the statement locks or writes a row: a locking read, an insert,
     * an update or a delete.
     *
     * @param  string  $sql
     * @return bool
     */
    private static function isLock(string $sql): bool
    {
        return preg_match('/^(insert|update|delete)\b/i', $sql) === 1 || preg_match('/ for (update|share|no key update)$| lock in share mode$/i', $sql) === 1;
    }

    /**
     * The table the statement reads, writes or locks first.
     *
     * @param  string  $sql
     * @return ?string
     */
    private static function tableOf(string $sql): ?string
    {
        return preg_match('/\b(?:from|into|update)\s+[`"]?(\w+)[`"]?/i', $sql, $match) === 1 ? $match[1] : null;
    }

    /**
     * The storage connection every member shares.
     *
     * @return \Illuminate\Database\Connection
     */
    private static function storage(): Connection
    {
        return DB::connection(StorageConnection::name());
    }
}
