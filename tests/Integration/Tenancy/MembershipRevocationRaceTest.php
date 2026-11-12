<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\IdentityMemberships;
use SineMacula\Laravel\Iam\Tenancy\TenantMembershipAdapter;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use Tests\Concerns\LinksByVerifiedDomain;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Tenancy\GuardedMemberships;
use Tests\Fixtures\Tenancy\StoredMembership;
use Tests\TestCase;

/**
 * Integration tests for a membership revoked during an activation's redemption.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantMembershipAdapter::class)]
#[CoversClass(IdentityMemberships::class)]
final class MembershipRevocationRaceTest extends TestCase
{
    use LinksByVerifiedDomain, MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The second connection the revocation is made on. */
    private const string ELSEWHERE = 'elsewhere';

    /** @var string What a revocation attempted during the redemption did when it waited on the guard. */
    private const string WAITED = 'waited';

    /** @var string What a revocation attempted during the redemption did when it deleted the membership. */
    private const string REVOKED = 'revoked';

    /**
     * Arrange SSO and a second connection that never waits long on a lock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::requireIsolationLevels();

        $this->arrangeSso();

        Config::set('database.connections.' . self::ELSEWHERE, Config::get('database.connections.' . self::CONNECTION));

        $elsewhere = DB::connection(self::ELSEWHERE);

        $elsewhere->statement($elsewhere->getDriverName() === 'pgsql' ? 'set lock_timeout = \'1s\'' : 'set session innodb_lock_wait_timeout = 1');
    }

    /**
     * Roll back what is left open, so the migrations' rollback never waits.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $elsewhere = $this->app?->make('db')->getConnections()[self::ELSEWHERE] ?? null;

        while ($elsewhere !== null && $elsewhere->transactionLevel() > 0) {
            $elsewhere->rollBack();
        }

        parent::tearDown();
    }

    /**
     * A revocation racing an activation waits for it and finds its session.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARevocationRacingAnActivationWaitsForItAndFindsItsSession(string $level): void
    {
        self::useIsolationLevel($level);
        self::useIsolationLevel($level, self::ELSEWHERE);

        $person = $this->createVerifiedPerson();

        StoredMembership::query()->create(['person_id' => $person->id, 'tenant_id' => self::TENANT, 'accepted_at' => now()->subDays(2)]);

        $this->verifyDomain();
        $this->grantsWithin();

        $handoff = $this->handoff(Purpose::SIGN_IN, tailor: self::byDomain());
        /** @var \ArrayObject<int, string> $attempts */
        $attempts = new \ArrayObject;

        self::onTheGuardedRead(function () use ($person, $attempts): void {
            $attempts->append($this->revokeDuringTheRedemption($person));
        });

        $signedIn = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $signedIn);
        self::assertTrue($signedIn->isSignedIn(), (string) $signedIn->reason?->value);
        self::assertSame([self::WAITED], $attempts->getArrayCopy(), 'The membership was revoked while the redemption that read it was open.');

        $link    = DB::table('sso_links')->where('identity_id', self::keyOf($person))->first() ?? self::fail('No link was activated.');
        $session = $signedIn->session->record                                                  ?? self::fail('No session was established.');

        self::assertSame(LinkOrigin::VERIFIED_DOMAIN->value, $link->provenance);
        self::assertSame([self::keyOf($session)], $this->revokeAndFindSessions($person));
    }

    /**
     * Bind the application's memberships before the seams are bound.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $app->bind(Memberships::class, GuardedMemberships::class);
    }

    /**
     * Run the callback once, after the redemption's guarded membership read.
     *
     * @param  \Closure(): void  $then
     * @return void
     */
    private static function onTheGuardedRead(\Closure $then): void
    {
        $ran = false;

        DB::connection(self::CONNECTION)->listen(static function (QueryExecuted $query) use (&$ran, $then): void {

            if ($ran || !self::isTheGuardedRead($query)) {
                return;
            }

            $ran = true;

            $then();
        });
    }

    /**
     * Whether the query is a locking memberships read in a transaction.
     *
     * @param  \Illuminate\Database\Events\QueryExecuted  $query
     * @return bool
     */
    private static function isTheGuardedRead(QueryExecuted $query): bool
    {
        $sql = strtolower($query->sql);

        return $query->connectionName === self::CONNECTION
            && $query->connection->transactionLevel() > 0
            && str_contains($sql, 'iam_memberships')
            && (str_contains($sql, 'for share') || str_contains($sql, 'lock in share mode'));
    }

    /**
     * Revoke on the other connection and report whether it deleted or waited.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return string
     *
     * @throws \Throwable
     */
    private function revokeDuringTheRedemption(Person $person): string
    {
        $elsewhere = DB::connection(self::ELSEWHERE);

        $elsewhere->beginTransaction();

        try {
            GuardedMemberships::revoke($person, self::TENANT, self::ELSEWHERE);

            $elsewhere->commit();

            return self::REVOKED;
        } catch (QueryException $exception) {
            return self::waitedOn($exception);
        } finally {
            while ($elsewhere->transactionLevel() > 0) {
                $elsewhere->rollBack();
            }
        }
    }

    /**
     * Revoke the membership, then find the person's live sessions.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return list<string>
     *
     * @throws \Throwable
     */
    private function revokeAndFindSessions(Person $person): array
    {
        return array_values(DB::connection(self::ELSEWHERE)->transaction(static function () use ($person): array {

            self::assertSame(1, GuardedMemberships::revoke($person, self::TENANT, self::ELSEWHERE));

            return DB::connection(self::ELSEWHERE)->table('authentication_sessions')
                ->where('authenticatable_id', self::keyOf($person))
                ->whereNull('revoked_at')
                ->pluck('id')
                ->map(static fn (mixed $id): string => is_scalar($id) ? (string) $id : self::fail('A session has no key.'))
                ->all();
        }));
    }

    /**
     * Whether the failure was a lock wait timeout; rethrows otherwise.
     *
     * @param  \Illuminate\Database\QueryException  $exception
     * @return string
     *
     * @throws \Illuminate\Database\QueryException
     */
    private static function waitedOn(QueryException $exception): string
    {
        if (($exception->errorInfo[1] ?? null) !== 1205 && ($exception->errorInfo[0] ?? null) !== '55P03') {
            throw $exception;
        }

        return self::WAITED;
    }
}
