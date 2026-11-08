<?php

declare(strict_types = 1);

namespace Tests\Integration\Audit;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Audit\DeferredRefusals;
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
 * Integration tests proving that a completion of MFA's that
 * `laravel-authentication` refuses leaves its refusal in the audit trail beside
 * MFA's own report (IAM-9.5), in audit-log's own tables on the storage
 * connection, the setup IAM-9.9's read refusal rests on.
 *
 * MFA hands a step-up, and a pending sign-in's completion, to this package's
 * adapters inside its own transaction. `laravel-authentication` reports a
 * refusal of either with `AuthenticationFailed` at once, inside that
 * transaction, and the adapter then throws, so MFA rolls the transaction back
 * and reports its own failed verification once it has. A record written at once
 * inside the transaction would roll back with it, leaving only MFA's generic
 * report; the refusal is held while the transaction is open and recorded once
 * it has rolled back (`DeferredRefusals`), with `laravel-authentication`'s own
 * reason. The session is changed inside MFA's transaction, once MFA has
 * accepted the proof and before the adapter is handed it, as a sign-out another
 * request commits at that moment would change it. Each runs at the connection's
 * own level on every engine, then at READ COMMITTED and REPEATABLE READ on
 * MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeferredRefusals::class)]
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
     * A step-up `laravel-authentication` refuses, its session revoked once MFA
     * accepted the factor, rolls MFA's transaction back and leaves both
     * reports: `laravel-authentication`'s refusal, with its own reason, then
     * MFA's failed verification.
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
     * A pending sign-in whose completion `laravel-authentication` refuses, its
     * session revoked once MFA accepted the factor, rolls MFA's transaction
     * back and leaves both reports: `laravel-authentication`'s refused sign-in,
     * with its own reason, then MFA's failed verification.
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
     * MFA's transaction, then hand the proof to this package's adapters.
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
