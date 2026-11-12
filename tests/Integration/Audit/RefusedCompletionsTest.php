<?php

declare(strict_types = 1);

namespace Tests\Integration\Audit;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthenticationEventMapper;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Iam\Mfa\StepUpAdapter;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesAuditLog;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Audit\ActsBeforeCompleting;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\TestCase;

/**
 * An MFA completion `laravel-authentication` refuses is recorded once MFA's
 * transaction rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationEventMapper::class)]
#[CoversClass(StepUpAdapter::class)]
#[CoversClass(PendingCompletionAdapter::class)]
#[WithConfig('audit-log.capture.laravel.except_guards', [self::GUARD])]
final class RefusedCompletionsTest extends TestCase
{
    use ArrangesFactorChanges, MigratesAuditLog, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The table audit-log keeps its entries in. */
    private const string ENTRIES = 'audit_log_entries';

    /** @var string The table `laravel-authentication` keeps its sessions in. */
    private const string SESSIONS = 'authentication_sessions';

    /**
     * A refused step-up leaves the refusal, with its own reason, then MFA's
     * failed verification.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusedStepUpIsRecordedOnceMfasTransactionHasRolledBack(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $factor  = $this->confirmedFactor($person);

        $this->changeBeforeCompleting(static function () use ($session): void {

            DB::table(self::SESSIONS)->where('id', $session->getKey())->update(['revoked_at' => CarbonImmutable::now()->subSecond(), 'revoked_reason' => 'signed_out']);
        });

        DB::table(self::ENTRIES)->delete();

        $result = Mfa::verify(self::callerOf($person), Submission::factor($factor->id, AuthenticatorApp::code($factor)), Purpose::STEP_UP);

        self::assertFalse($result->isVerified());
        self::assertSame(0, DB::connection()->transactionLevel());
        self::assertSame([
            ['session.step_up_failed', 'failure', 'session_revoked'],
            ['mfa.verification_failed', 'failure', 'not_accepted'],
        ], self::entries());
    }

    /**
     * A refused pending completion leaves the refused sign-in, then MFA's
     * failed verification.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusedPendingCompletionIsRecordedOnceMfasTransactionHasRolledBack(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();
        $factor = $this->confirmedFactor($person);
        $signIn = $this->attemptSignIn($person);

        self::assertTrue($signIn->isPending());
        self::assertNotNull($signIn->credential);

        $this->changeBeforeCompleting(static function (): void {

            DB::table(self::SESSIONS)->update(['revoked_at' => CarbonImmutable::now()->subSecond(), 'revoked_reason' => 'signed_out']);
        });

        DB::table(self::ENTRIES)->delete();

        $caller = CallerContext::fromRequest(Request::create('/mfa/verify', 'POST', ['pending_credential' => $signIn->credential->reveal()]));
        $result = Mfa::verify($caller, Submission::factor($factor->id, AuthenticatorApp::code($factor)), Purpose::SIGN_IN);

        self::assertFalse($result->isVerified());
        self::assertSame(0, DB::connection()->transactionLevel());
        self::assertSame([
            ['authentication.sign_in_failed', 'failure', 'pending_invalid'],
            ['mfa.verification_failed', 'failure', 'not_accepted'],
        ], self::entries());
    }

    /**
     * Have MFA's step-up and pending completion make the change first, inside
     * MFA's transaction.
     *
     * @param  \Closure(): void  $change
     * @return void
     */
    private function changeBeforeCompleting(\Closure $change): void
    {
        $app = $this->app;

        self::assertNotNull($app);

        $acting = new ActsBeforeCompleting($app->make(StepUpAdapter::class), $app->make(PendingCompletionAdapter::class), $change);

        $app->instance(StepUp::class, $acting);
        $app->instance(PendingCompletion::class, $acting);
    }

    /**
     * Every entry audit-log holds, oldest first, as its code, outcome and
     * reason.
     *
     * @return list<list<mixed>>
     */
    private static function entries(): array
    {
        return array_values(array_map(
            static fn (object $row): array => [$row->event ?? null, $row->outcome ?? null, $row->reason ?? null],
            DB::table(self::ENTRIES)->orderBy('occurred_at')->orderBy('id')->get()->all(),
        ));
    }
}
