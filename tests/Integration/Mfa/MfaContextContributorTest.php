<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Iam\Mfa\MfaContextContributor;
use SineMacula\Laravel\Iam\Mfa\SignInProofs;
use SineMacula\Laravel\Iam\Testing\Concerns\InteractsWithIam;
use SineMacula\Laravel\Mfa\Context\AuthenticationContextContributor as MfaContributor;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Concerns\ChangesSessionsElsewhere;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\ContributesInAJob;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for the `mfa` namespace of `laravel-authentication`'s
 * authentication context (IAM-3.12): the keys are MFA's own, worked out from
 * the contribution subject's session and its proofs, so the request's context
 * agrees with MFA's own view of the caller, a context built for another session
 * than the request's reports that session's verification, and one built in a
 * queued job, with no request and no guard bound, reports the session it names.
 * A session no longer live, a subject with no session and an identity that
 * cannot hold factors get the neutral context; a first factor older than every
 * proof read still counts; and inside a transaction the proofs are read
 * current, so a removal committed after the transaction's first read shows. The
 * request's context is built once and kept, so one built before a transaction
 * is returned unchanged inside it, as `laravel-authentication` keeps it, while
 * MFA's own view is asked afresh there.
 *
 * Each scenario that reads stored proofs runs at the connection's own level on
 * every engine, then at READ COMMITTED and REPEATABLE READ on MySQL and
 * PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaContextContributor::class)]
#[CoversClass(SignInProofs::class)]
final class MfaContextContributorTest extends TestCase
{
    use ChangesSessionsElsewhere, InteractsWithIam, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The table `laravel-authentication` keeps each session's proofs in. */
    private const string PROOFS = 'authentication_proofs';

    /**
     * Forget what an earlier job contributed.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        ContributesInAJob::$contributed = null;

        parent::tearDown();
    }

    /**
     * The request's context holds MFA's own view of the caller under `mfa`:
     * before the session is verified and once it is.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheRequestsContextIsMfasOwnView(?string $level): void
    {
        self::runAtIsolationLevel($level);

        // MFA's view and the context are each worked out as of their own call,
        // so the clock stands still for the evidence's age to compare equal.
        $this->freezeSecond();

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        self::assertFalse($this->context()->get('mfa.accepted'));
        self::assertSame(Mfa::authenticationContext(self::callerOf($person)), $this->mfaKeys());

        $this->actingOnVerifiedSession($session);

        $keys = $this->mfaKeys();

        self::assertSame(Mfa::authenticationContext(self::callerOf($person)), $keys);
        self::assertTrue($keys['accepted']);
        self::assertTrue($keys['multifactor']);
        self::assertSame(['totp'], $keys['factor_types']);
        self::assertSame(AssuranceLevel::AAL2->value, $keys['level']);
        self::assertTrue($keys['has_confirmed_factor']);
        self::assertIsInt($keys['last_verification_age_seconds']);
    }

    /**
     * The proofs reach MFA oldest first, so the age reported is the newest
     * verification's.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheAgeIsTheNewestVerifications(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);
        $this->travel(10)->minutes();
        $this->actingOnVerifiedSession($session);
        $this->travel(5)->seconds();

        self::assertSame(5, $this->contributed($person, $session)['last_verification_age_seconds']);
    }

    /**
     * Proofs made at the same instant reach MFA in the order
     * `laravel-authentication` reads them back (by their ids), oldest first, so
     * the factor types come in that order.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testProofsMadeAtOneInstantKeepTheirOrder(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());

        $this->actingOnVerifiedSession($session, AssuranceLevel::AAL1);
        $this->actingOnVerifiedSession($session);

        $further = DB::table(self::PROOFS)->where('kind', 'additional_factor')->orderBy('id')->pluck('method')->all();

        self::assertCount(2, $further);
        self::assertSame($further, $this->contributed($person, $session)['factor_types']);
    }

    /**
     * A context built for another session than the request's reports that
     * session's verification, never the request's.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnotherSessionsContextIsItsOwn(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person     = $this->createPerson();
        $unverified = $this->signIn($person)->record;
        $verified   = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($verified);
        $this->actingOnSession($unverified, self::GUARD);

        self::assertTrue($this->contributed($person, $verified)['accepted']);
        self::assertSame(['totp'], $this->contributed($person, $verified)['factor_types']);
        self::assertFalse($this->contributed($person, $unverified)['accepted']);
        self::assertSame([], $this->contributed($person, $unverified)['factor_types']);
        self::assertFalse($this->context()->get('mfa.accepted'));

        $this->actingOnSession($verified, self::GUARD);

        self::assertFalse($this->contributed($person, $unverified)['accepted']);
        self::assertTrue($this->context()->get('mfa.accepted'));
    }

    /**
     * A context built in a queued job, with no request and no guard bound,
     * reports the session the job names.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAJobsContextIsTheNamedSessions(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person     = $this->createPerson();
        $unverified = $this->signIn($person)->record;
        $verified   = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($verified);
        $this->actingOnSession($unverified, self::GUARD);

        dispatch(new ContributesInAJob($person->id, self::keyOf($verified), self::GUARD));

        self::assertNotNull(ContributesInAJob::$contributed);
        self::assertTrue(ContributesInAJob::$contributed['accepted']);
        self::assertSame(['totp'], ContributesInAJob::$contributed['factor_types']);

        $this->actingOnSession($verified, self::GUARD);

        dispatch(new ContributesInAJob($person->id, self::keyOf($unverified), self::GUARD));

        self::assertNotNull(ContributesInAJob::$contributed);
        self::assertFalse(ContributesInAJob::$contributed['accepted']);
        self::assertSame([], ContributesInAJob::$contributed['factor_types']);
        self::assertTrue(ContributesInAJob::$contributed['has_confirmed_factor']);
    }

    /**
     * A session that is no longer live gets the neutral context, without MFA
     * being asked: not even the confirmed factor the person holds is reported.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testASessionNoLongerLiveIsNeutral(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);

        self::assertTrue($this->contributed($person, $session)['has_confirmed_factor']);

        $this->sessions()->revokeSession($person, $session->getKey(), RevocationReason::REVOKED);

        self::assertSame(MfaContributor::neutral(), $this->contributed($person, $session));
    }

    /**
     * A subject with no session, and one whose identity cannot hold factors,
     * get the neutral context.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoSessionAndAnIdentityThatCannotHoldFactorsAreNeutral(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);

        $context  = ContributesInAJob::subject($person, $session, self::GUARD)->context;
        $stranger = \Mockery::mock(Identity::class, Principal::class);

        self::assertSame(MfaContributor::neutral(), $this->contributor()->contribute(new ContributionSubject($context, $person, $person, null, null)));
        self::assertSame(MfaContributor::neutral(), $this->contributor()->contribute(new ContributionSubject($context, $stranger, $stranger, null, $session)));
    }

    /**
     * The session's first factor counts when it is older than every proof read:
     * MFA reports evidence only after exactly one first factor, and the newest
     * of the proofs read is the newest evidence.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAFirstFactorOlderThanEveryProofReadStillCounts(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->travel(1)->minutes();
        $this->actingOnVerifiedSession($session);

        $further  = (array) (DB::table(self::PROOFS)->where('kind', 'additional_factor')->first() ?? self::fail('No further proof was recorded.'));
        $verified = CarbonImmutable::now()->startOfSecond();

        for ($copy = 1; $copy <= RequirementSubject::MAX_LIMIT; $copy++) {
            DB::table(self::PROOFS)->insert([...$further, 'id' => (string) Str::uuid(), 'authenticated_at' => $verified->addSeconds($copy)]);
        }

        CarbonImmutable::setTestNow($verified->addSeconds(RequirementSubject::MAX_LIMIT));

        $keys = $this->contributed($person, $session);

        self::assertTrue($keys['accepted']);
        self::assertSame(['totp'], $keys['factor_types']);
        self::assertSame(0, $keys['last_verification_age_seconds']);
    }

    /**
     * A session whose first factor no longer counts is asked of MFA with its
     * further proofs alone, which MFA reports no evidence for.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testASessionWhoseFirstFactorNoLongerCountsReportsNoEvidence(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);

        DB::table(self::PROOFS)->where('kind', 'first_factor')->update(['voided_at' => CarbonImmutable::now()]);

        $keys = $this->contributed($person, $session);

        self::assertSame([], $keys['factor_types']);
        self::assertNull($keys['last_verification_age_seconds']);
        self::assertTrue($keys['has_confirmed_factor']);
    }

    /**
     * Inside a transaction the proofs are read current: a removal committed on
     * another connection after the transaction's first read shows, as the
     * contributor answers once the session's row is locked.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testInsideATransactionTheProofsAreReadCurrent(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);

        $factor = $this->factorOf($person);

        self::assertTrue($this->contributed($person, $session)['accepted']);

        $accepted = $this->askedAfter(
            $level,
            fn () => $this->removeElsewhere($person, $session, $factor),
            fn (): mixed => $this->contributed($person, $session)['accepted'],
        );

        self::assertFalse($accepted);
    }

    /**
     * The request's context is built once and kept: one built before a
     * transaction is returned unchanged inside it, with no query run and so no
     * lock taken, after another process has voided the session's proofs, while
     * MFA's own view of the caller, asked inside the same transaction, reads
     * the proofs current.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAContextBuiltBeforeATransactionIsKeptInsideIt(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);

        self::assertTrue($this->context()->get('mfa.accepted'));

        // Another process voids the proofs: a plain write on another
        // connection, which this process's guard is not told of.
        $this->elsewhere(static fn (): int => DB::table(self::PROOFS)->update(['voided_at' => CarbonImmutable::now()]));

        $storage = DB::connection(StorageConnection::name());

        $storage->enableQueryLog();

        [$kept, $keptQueries, $current, $currentQueries] = $storage->transaction(function () use ($person, $storage): array {

            $storage->flushQueryLog();

            $kept        = $this->context()->get('mfa.accepted');
            $keptQueries = count($storage->getQueryLog());

            $storage->flushQueryLog();

            $current = Mfa::authenticationContext(self::callerOf($person))['accepted'];

            return [$kept, $keptQueries, $current, count($storage->getQueryLog())];
        });

        self::assertTrue($kept);
        self::assertSame(0, $keptQueries);
        self::assertFalse($current);
        self::assertGreaterThan(0, $currentQueries);
    }

    /**
     * The `mfa` keys the registered contributor gives the person's session,
     * read afresh.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    private function contributed(Person $person, EloquentSession&Model $session): array
    {
        $fresh = $session->fresh();

        self::assertInstanceOf(EloquentSession::class, $fresh);

        return $this->contributor()->contribute(ContributesInAJob::subject($person, $fresh, self::GUARD));
    }

    /**
     * The contributor registered under `mfa`.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\MfaContextContributor
     *
     * @throws \LogicException
     */
    private function contributor(): MfaContextContributor
    {
        $contributor = ContributesInAJob::contributor();

        self::assertInstanceOf(MfaContextContributor::class, $contributor);

        return $contributor;
    }

    /**
     * The request's authentication context.
     *
     * @return \SineMacula\Laravel\Authentication\Context\AuthenticationContext
     */
    private function context(): AuthenticationContext
    {
        return Auth::context() ?? self::fail('No authentication context was built.');
    }

    /**
     * The `mfa` keys of the request's authentication context.
     *
     * @return array<array-key, mixed>
     */
    private function mfaKeys(): array
    {
        $keys = $this->context()->toArray()['mfa'] ?? null;

        return is_array($keys) ? $keys : self::fail('The context holds no `mfa` keys.');
    }

    /**
     * The id of the factor the person's verification was made with.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return string
     */
    private function factorOf(Person $person): string
    {
        $factor = $person->authFactors()->first();

        self::assertInstanceOf(Factor::class, $factor);

        return SignInProofs::factorReference($factor);
    }

    /**
     * The session's key, as the job names it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @return string
     */
    private static function keyOf(Model $session): string
    {
        $key = $session->getKey();

        return is_string($key) ? $key : self::fail('The session has no key.');
    }
}
