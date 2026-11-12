<?php

declare(strict_types = 1);

namespace Tests\Integration\Audit;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\External\NoExternalLinks;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Audit\Correlation;
use SineMacula\Laravel\Iam\Exceptions\ExternalReauthenticationRefusedException;
use SineMacula\Laravel\Iam\Exceptions\ExternalSignInRefusedException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption;
use SineMacula\Laravel\Iam\Sso\SignInRedemption;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use Tests\Concerns\MigratesAuditLog;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\TestCase;

/**
 * A refused redemption rolls back and its refusal is recorded once, after the
 * rollback (IAM-9.5), on every engine and isolation level.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInRedemption::class)]
#[CoversClass(ReauthenticationRedemption::class)]
#[WithConfig('audit-log.capture.laravel.except_guards', [self::GUARD])]
final class RefusedRedemptionsTest extends TestCase
{
    use MigratesAuditLog, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The table audit-log keeps its entries in. */
    private const string ENTRIES = 'audit_log_entries';

    /**
     * Arrange SSO for the guard.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();
    }

    /**
     * A refused external sign-in rolls its redemption back and is recorded
     * once, after the rollback, as `authentication.sign_in_failed` with
     * `laravel-authentication`'s reason, correlated as the SSO sign-in it
     * ended.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusedSignInIsRecordedOnceTheRedemptionHasRolledBack(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->linkThroughFlow($this->createPerson());

        $handoff = $this->handoff();

        $this->allowExternalSignIn(false);

        DB::table(self::ENTRIES)->delete();

        $refusal = self::thrownBy(fn (): mixed => Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client())));

        self::assertInstanceOf(ExternalSignInRefusedException::class, $refusal);
        self::assertSame(0, DB::connection()->transactionLevel());
        self::assertSame([
            ['authentication.sign_in_failed', 'failure', 'method_not_allowed', Correlation::ssoSignIn($this->connectionId, $handoff->reference)],
        ], self::entries());
    }

    /**
     * A refused external re-authentication rolls its redemption back and is
     * recorded once, after the rollback, as `session.reauthentication_failed`
     * with `laravel-authentication`'s reason, correlated as the SSO flow it
     * ended.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusedReauthenticationIsRecordedOnceTheRedemptionHasRolledBack(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        $this->linkThroughFlow($person);

        $signIn = $this->handoff();
        $answer = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $signIn->code, $signIn->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertNotNull($answer->session);

        $this->travel(30)->seconds();

        $handoff = $this->handoff(Purpose::REAUTHENTICATE, $person, self::keyOf($answer->session->record));

        $this->app?->instance(ExternalIdentityLinks::class, new NoExternalLinks);

        DB::table(self::ENTRIES)->delete();

        $refusal = self::thrownBy(fn (): mixed => Iam::reauthentications()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client()));

        self::assertInstanceOf(ExternalReauthenticationRefusedException::class, $refusal);
        self::assertSame(0, DB::connection()->transactionLevel());
        self::assertSame([
            ['session.reauthentication_failed', 'failure', 'external_result_unlinked', Correlation::ssoSignIn($this->connectionId, $handoff->reference)],
        ], self::entries());
    }

    /**
     * Every entry audit-log holds, oldest first, as its code, outcome, reason
     * and correlation.
     *
     * @return list<list<mixed>>
     */
    private static function entries(): array
    {
        return array_values(array_map(
            static fn (object $row): array => [$row->event ?? null, $row->outcome ?? null, $row->reason ?? null, $row->correlation_id ?? null],
            DB::table(self::ENTRIES)->orderBy('occurred_at')->orderBy('id')->get()->all(),
        ));
    }

    /**
     * Allow, or stop allowing, sign-in through an external provider on the
     * guard, as its configuration would, for the guards resolved from now on.
     *
     * @param  bool  $allowed
     * @return void
     */
    private function allowExternalSignIn(bool $allowed): void
    {
        Config::set('auth.guards.' . self::GUARD . '.application.methods', $allowed ? ['password', 'external_provider'] : ['password']);

        $this->app?->make('auth')->forgetGuards();
    }

    /**
     * What the call threw, failing when it threw nothing.
     *
     * @param  \Closure(): mixed  $call
     * @return \Throwable
     */
    private static function thrownBy(\Closure $call): \Throwable
    {
        try {
            $call();
        } catch (\Throwable $thrown) {
            return $thrown;
        }

        self::fail('The call threw nothing.');
    }
}
