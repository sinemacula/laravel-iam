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
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
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
 * Integration tests for an enforcement change racing a sign-in through SSO in
 * the enforcing tenant, with the tenant authentication policy this package
 * binds (IAM-4.4, IAM-4.5), against SSO's acceptance scenario: the sign-in
 * either sees the new rule or the session it writes is judged against it.
 *
 * The change commits on another database connection after the redemption has
 * read its code and before it locks the enforcing tenant's rule, on MySQL and
 * PostgreSQL at READ COMMITTED and REPEATABLE READ. A rule that no longer
 * admits the connection refuses the sign-in, which signs nobody in; one that
 * still admits it signs the person in, the provenance naming the rule SSO
 * locked, and the session is kept by the next judgement of the tenant's
 * sessions, which records the version the policy answers now, whatever older
 * snapshot the sign-in's own judgement read.
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
     * Arrange SSO with its enforcement on, a tenancy in which everyone may act
     * in every tenant, a linked person who has signed in once, a rule through
     * the tests' connection, and a second connection of the tenant SSO may
     * enforce.
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
     * A rule changed to one that no longer admits the connection, after the
     * sign-in read its code and before it locked, refuses the sign-in: nobody
     * is signed in, and on PostgreSQL at REPEATABLE READ the sign-in is first
     * run again from its start, once.
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
     * A rule changed to one that still admits the connection, after the sign-in
     * read its code and before it locked, signs the person in: the provenance
     * names the rule SSO locked, and the next judgement of the tenant's
     * sessions keeps the session and records the version the policy answers for
     * it now.
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

        $policy = $this->app?->make(TenantAuthenticationPolicy::class) ?? self::fail('The application has not booted.');
        $now    = $policy->requirementFor(new TenantPolicyContext(self::GUARD, $answer->session->identity, $answer->session->principal, new ClaimedTenant(self::TENANT), $stored));

        self::assertNull($stored->getRevokedAt());
        self::assertSame($now->version, $stored->getTenantPolicyVersion());
    }

    /**
     * Require every session acting in the tenant to come through one of the
     * connections, and answer the rule's version.
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

        return $result->enforcement->version ?? self::fail('The enforcement has no version.');
    }

    /**
     * Redeem the handoff for the guard through the connection, the sign-in
     * asking to act in the tenant.
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
     * Make the change on another connection to the same database, committed
     * there, the first time the redemption reads its code inside its
     * transaction (after it read, before it locked), and record each time it
     * reads it.
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
     * Whether the isolation level and driver run a redemption again that locks
     * a row another committed after it read: PostgreSQL's REPEATABLE READ.
     *
     * @param  string  $level
     * @return bool
     */
    private static function isSnapshotRetried(string $level): bool
    {
        return DB::connection()->getDriverName() === 'pgsql' && $level === 'repeatable read';
    }
}
