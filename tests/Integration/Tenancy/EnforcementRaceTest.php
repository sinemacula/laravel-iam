<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext as SsoClientContext;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Sso\Handoff;
use Tests\TestCase;

/**
 * Integration tests for an enforcement change racing an SSO sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantAuthenticationPolicyAdapter::class)]
final class EnforcementRaceTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The second connection the change is made on. */
    private const string ELSEWHERE = 'elsewhere';

    /** @var string The IP address the change comes from. */
    private const string OTHER_IP = '192.0.2.99';

    /** @var string A second connection of the tenant, which has completed a sign-in. */
    private string $otherConnectionId = '';

    /**
     * Arrange SSO enforcement, a linked person, a rule and a second connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::requireIsolationLevels();

        $this->arrangeSso();

        Config::set('sso.features.enforcement', true);

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);

        $this->linkThroughFlow($this->createPerson());

        self::assertInstanceOf(SignInResult::class, $this->redeemInTenant($this->handoff()));

        $this->enforceThrough([$this->connectionId]);

        $this->otherConnectionId = $this->makeConnection();

        DB::table('sso_connections')->where('id', $this->otherConnectionId)->update(['has_completed_sign_in' => true]);
    }

    /**
     * A rule that no longer admits the connection refuses the sign-in.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARuleThatNoLongerAdmitsTheConnectionRefusesTheSignIn(string $level): void
    {
        self::useIsolationLevel($level);

        $handoff  = $this->handoff();
        $sessions = DB::table('authentication_sessions')->count();
        $runs     = $this->whenTheCodeIsRead(fn () => $this->enforceThrough([$this->otherConnectionId], new SsoClientContext(self::OTHER_IP, null)));
        $answer   = $this->redeemInTenant($handoff);

        self::assertInstanceOf(RedemptionResult::class, $answer);
        self::assertTrue($answer->isRefused());
        self::assertSame(FailureReason::ENFORCEMENT_UNSATISFIED, $answer->reason);
        self::assertSame($sessions, DB::table('authentication_sessions')->count());
        self::assertCount(self::isSnapshotRetried($level) ? 2 : 1, $runs);
    }

    /**
     * A rule that still admits the connection signs in and is judged now.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARuleThatStillAdmitsTheConnectionSignsInAndIsJudgedAsItIsNow(string $level): void
    {
        self::useIsolationLevel($level);

        $handoff = $this->handoff();
        /** @var \ArrayObject<int, string> $changed */
        $changed = new \ArrayObject;

        $this->whenTheCodeIsRead(function () use ($changed): void {
            $changed->append($this->enforceThrough([$this->connectionId, $this->otherConnectionId], new SsoClientContext(self::OTHER_IP, null)));
        });

        $answer = $this->redeemInTenant($handoff);

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn(), (string) $answer->reason?->value);

        $session = $answer->session->record ?? self::fail('The sign-in established no session.');
        $judged  = DB::table('authentication_provenance')->where('session_id', self::keyOf($session))->value('policy_version');

        self::assertSame($changed[0], $judged);

        $this->sessions()->tenantPolicyChanged(new ClaimedTenant(self::TENANT));

        $stored = $session->newQuery()->find($session->getKey());

        self::assertInstanceOf(EloquentSession::class, $stored);

        $policy   = $this->app?->make(TenantAuthenticationPolicy::class) ?? self::fail('The application has not booted.');
        $signedIn = $answer->session;
        $through  = fn (): ?string => $this->recordedConnectionOf($stored);
        $context  = self::tenantPolicyContext($signedIn->identity, $signedIn->principal, new ClaimedTenant(self::TENANT), $stored, $through);
        $now      = $policy->requirementFor($context);

        self::assertNull($stored->getRevokedAt());
        self::assertSame($now->version, $stored->getTenantPolicyVersion());
    }

    /**
     * Require sessions to come through the connections; return the policy
     * version a session is judged at.
     *
     * @param  list<string>  $connections
     * @param  ?\SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return string
     */
    private function enforceThrough(array $connections, ?SsoClientContext $client = null): string
    {
        $service = $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');
        $result  = $service->update(self::TENANT, true, $connections, $client ?? self::ssoClient());

        self::assertTrue($result->isChanged(), sprintf('The enforcement did not change: [%s].', $result->reason->value ?? $result->status->value));

        $tenantId = $result->enforcement->tenantId ?? self::fail('The change named no enforcement.');

        return $this->app->make(Enforcement::class)->policy($tenantId, self::GUARD)->version ?? self::fail('The policy has no version.');
    }

    /**
     * Redeem the handoff, asking to act in the tenant.
     *
     * @param  \Tests\Fixtures\Sso\Handoff  $handoff
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function redeemInTenant(Handoff $handoff): RedemptionResult|SignInResult
    {
        $context = new SignInContext(self::client(), tenant: TenantSelection::of(self::TENANT));

        return Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, $context);
    }

    /**
     * Commit the change elsewhere when the redemption first reads its code.
     *
     * @param  \Closure(): mixed  $change
     * @return \ArrayObject<int, true>
     */
    private function whenTheCodeIsRead(\Closure $change): \ArrayObject
    {
        Config::set('database.connections.' . self::ELSEWHERE, Config::get('database.connections.' . self::CONNECTION));

        $elsewhere = DB::connection(self::ELSEWHERE);

        // Never wait long on a lock the redemption holds.
        $elsewhere->statement($elsewhere->getDriverName() === 'pgsql' ? 'set lock_timeout = \'5s\'' : 'set session innodb_lock_wait_timeout = 5');

        /** @var \ArrayObject<int, true> $runs */
        $runs = new \ArrayObject;

        DB::connection(self::CONNECTION)->listen(static function (QueryExecuted $query) use ($runs, $change): void {

            $sql      = strtolower($query->sql);
            $readCode = str_starts_with($sql, 'select') && str_contains($sql, 'sso_handoff_codes') && !str_contains($sql, 'for update');

            if ($query->connectionName !== self::CONNECTION || $query->connection->transactionLevel() === 0 || !$readCode) {
                return;
            }

            $runs->append(true);

            if ($runs->count() > 1) {
                return;
            }

            $default = DB::getDefaultConnection();

            DB::setDefaultConnection(self::ELSEWHERE);

            try {
                $change();
            } finally {
                DB::setDefaultConnection($default);
            }
        });

        return $runs;
    }

    /**
     * Whether a redemption is retried after a snapshot conflict.
     *
     * @param  string  $level
     * @return bool
     */
    private static function isSnapshotRetried(string $level): bool
    {
        return DB::connection()->getDriverName() === 'pgsql' && $level === 'repeatable read';
    }
}
