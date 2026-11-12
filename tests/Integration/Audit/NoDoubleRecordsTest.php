<?php

declare(strict_types = 1);

namespace Tests\Integration\Audit;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use Tests\Concerns\MigratesAuditLog;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\TestCase;

/**
 * Integration tests that nothing reported on a `jwt` or `api_key` guard is
 * recorded twice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureExclusions::class)]
final class NoDoubleRecordsTest extends TestCase
{
    use MigratesAuditLog, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The table audit-log keeps its entries in. */
    private const string ENTRIES = 'audit_log_entries';

    /** @var string The `api_key` guard the tests configure beside the `jwt` one. */
    private const string API_KEY_GUARD = 'keys';

    /**
     * Rows of `[isolation level, excluded, records]`: once excluded, twice not.
     *
     * @return iterable<string, array{0: ?string, 1: bool, 2: int}>
     */
    public static function provideExclusions(): iterable
    {
        foreach (self::provideEveryIsolationLevel() as $level => [$isolation]) {

            yield $level . ', excluded' => [$isolation, true, 1];

            yield $level . ', not excluded' => [$isolation, false, 2];
        }
    }

    /**
     * A sign-in is recorded once while the guard is excluded, and twice while
     * it is not.
     *
     * @param  ?string  $level
     * @param  bool  $excluded
     * @param  int  $records
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideExclusions')]
    public function testASignInIsRecordedOnce(?string $level, bool $excluded, int $records): void
    {
        self::runAtIsolationLevel($level);

        $this->exclude($excluded);

        $person = $this->createPerson();

        DB::table(self::ENTRIES)->delete();

        $this->signIn($person);

        self::assertSame($records, $this->recorded(CapturedActivity::SIGNED_IN->value));
        self::assertNoCodeRecordedTwiceWhile($excluded);
    }

    /**
     * A refused sign-in is recorded once while the guard is excluded, and twice
     * while it is not.
     *
     * @param  ?string  $level
     * @param  bool  $excluded
     * @param  int  $records
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideExclusions')]
    public function testARefusedSignInIsRecordedOnce(?string $level, bool $excluded, int $records): void
    {
        self::runAtIsolationLevel($level);

        $this->exclude($excluded);

        $person = $this->createPerson();

        DB::table(self::ENTRIES)->delete();

        $result = $this->sessions()->signIn('password', ['email' => $person->email, 'password' => 'not the password'], new SignInContext(self::client()));

        self::assertFalse($result->isSignedIn());
        self::assertSame($records, $this->recorded(CapturedActivity::SIGN_IN_FAILED->value));
        self::assertNoCodeRecordedTwiceWhile($excluded);
    }

    /**
     * Rows of `[isolation level, excluded, records]`: none excluded, once by
     * audit-log's capture not.
     *
     * @return iterable<string, array{0: ?string, 1: bool, 2: int}>
     */
    public static function provideAttemptExclusions(): iterable
    {
        foreach (self::provideEveryIsolationLevel() as $level => [$isolation]) {

            yield $level . ', excluded' => [$isolation, true, 0];

            yield $level . ', not excluded' => [$isolation, false, 1];
        }
    }

    /**
     * An `attempt()` sign-in is recorded only by audit-log's capture, so not at
     * all once excluded.
     *
     * @param  ?string  $level
     * @param  bool  $excluded
     * @param  int  $records
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideAttemptExclusions')]
    public function testAnAttemptsSignInIsRecordedOnlyByAuditLogsCapture(?string $level, bool $excluded, int $records): void
    {
        self::runAtIsolationLevel($level);

        $this->exclude($excluded);

        $person = $this->createPerson();

        DB::table(self::ENTRIES)->delete();

        self::assertTrue(Auth::guard(self::GUARD)->attempt(['email' => $person->email, 'password' => self::PASSWORD]));
        self::assertSame($records, $this->recorded(CapturedActivity::SIGNED_IN->value));
        self::assertSame($records, DB::table(self::ENTRIES)->count());
    }

    /**
     * A refused `attempt()` is recorded once while the guard is excluded, and
     * twice while it is not.
     *
     * @param  ?string  $level
     * @param  bool  $excluded
     * @param  int  $records
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideExclusions')]
    public function testARefusedAttemptIsRecordedOnce(?string $level, bool $excluded, int $records): void
    {
        self::runAtIsolationLevel($level);

        $this->exclude($excluded);

        $person = $this->createPerson();

        DB::table(self::ENTRIES)->delete();

        self::assertFalse(Auth::guard(self::GUARD)->attempt(['email' => $person->email, 'password' => 'not the password']));
        self::assertSame($records, $this->recorded(CapturedActivity::SIGN_IN_FAILED->value));
        self::assertNoCodeRecordedTwiceWhile($excluded);
    }

    /**
     * A sign-out is recorded once while the guard is excluded, and twice while
     * it is not.
     *
     * @param  ?string  $level
     * @param  bool  $excluded
     * @param  int  $records
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideExclusions')]
    public function testASignOutIsRecordedOnce(?string $level, bool $excluded, int $records): void
    {
        self::runAtIsolationLevel($level);

        $this->exclude($excluded);

        $this->signInAndActOnSession($this->createPerson());

        DB::table(self::ENTRIES)->delete();

        self::assertTrue($this->sessions()->signOut());
        self::assertSame($records, $this->recorded(CapturedActivity::SIGNED_OUT->value));
        self::assertNoCodeRecordedTwiceWhile($excluded);
    }

    /**
     * An `api_key` guard's sign-out is recorded only by audit-log's capture, so
     * not at all once excluded.
     *
     * @param  ?string  $level
     * @param  bool  $excluded
     * @param  int  $records
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideAttemptExclusions')]
    public function testAnApiKeyGuardsSignOutIsRecordedOnlyByAuditLogsCapture(?string $level, bool $excluded, int $records): void
    {
        self::runAtIsolationLevel($level);

        $config = $this->app?->make('config') ?? self::fail('The application has not booted.');

        $config->set('auth.guards.' . self::API_KEY_GUARD, ['driver' => 'api_key', 'provider' => 'people']);

        $this->exclude($excluded, [self::GUARD, self::API_KEY_GUARD]);

        $person = $this->createPerson();
        $guard  = Auth::guard(self::API_KEY_GUARD);

        $guard->setUser($person);

        DB::table(self::ENTRIES)->delete();

        $guard->logout();

        self::assertSame($records, $this->recorded(CapturedActivity::SIGNED_OUT->value));
        self::assertSame($records, DB::table(self::ENTRIES)->count());
    }

    /**
     * Write the exclusions `CaptureExclusions` computes, or leave every guard
     * captured.
     *
     * @param  bool  $excluded
     * @param  list<string>  $guards
     * @return void
     */
    private function exclude(bool $excluded, array $guards = [self::GUARD]): void
    {
        $config     = $this->app?->make('config') ?? self::fail('The application has not booted.');
        $exclusions = new CaptureExclusions($config);

        self::assertSame($guards, $exclusions->unexcludedGuards());

        if (!$excluded) {
            return;
        }

        $config->set(CaptureExclusions::EXCEPT_GUARDS_KEY, $exclusions->exceptGuards());

        self::assertTrue($exclusions->holds());
    }

    /**
     * How many entries audit-log holds of the code.
     *
     * @param  string  $code
     * @return int
     */
    private function recorded(string $code): int
    {
        return DB::table(self::ENTRIES)->where('event', $code)->count();
    }

    /**
     * Fail while the guard is excluded and any code was recorded more than
     * once.
     *
     * @param  bool  $excluded
     * @return void
     */
    private static function assertNoCodeRecordedTwiceWhile(bool $excluded): void
    {
        if (!$excluded) {
            return;
        }

        /** @var list<string> $codes */
        $codes = DB::table(self::ENTRIES)->pluck('event')->all();

        self::assertSame(array_values(array_unique($codes)), $codes, 'A code was recorded twice: ' . implode(', ', $codes));
    }
}
