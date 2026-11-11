<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\SessionTransitionAdapter;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\SessionTransitionTests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RecordsRequirementDecisions;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\TestCase;

/**
 * Integration tests for MFA's session transition through
 * `laravel-authentication` (IAM-3.8): MFA's contract kit, the session MFA names
 * judged again by `laravel-authentication`'s rules, whatever the guard holds,
 * and its result returned as MFA's completion, a session that falls short
 * returned to pending with a new credential, and a change on a sign-in that is
 * no session of the identity's refused by throwing so the change rolls back
 * unjudged (IAM-8.2).
 *
 * MFA's own flow is run too: confirming an enrolment on an active session, with
 * this package's factor-change adapters bound alone, judges the session last,
 * locking its row after MFA's own, on MySQL and PostgreSQL at READ COMMITTED
 * and REPEATABLE READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionTransitionAdapter::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class SessionTransitionAdapterTest extends TestCase
{
    use ArrangesFactorChanges, MigratesMembers, RecordsRequirementDecisions, RunsAtIsolationLevels, SessionTransitionTests, SignsInPeople;

    /**
     * Each change MFA made is judged by `laravel-authentication`, whose result
     * is the completion: a session still meeting its requirement stays active.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachChangeIsJudgedAndTheResultReturned(): void
    {
        foreach (FactorChangeMade::cases() as $made) {

            $change = $this->sessionChange($made);
            $result = $this->transition()->factorChanged($change);

            self::assertTrue($result->isActive(), sprintf('The session was not kept active after [%s].', $made->value));
        }
    }

    /**
     * The decisions `laravel-authorization` keeps for the request are forgotten
     * once the session the change was made on is judged again (IAM-6.11).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDecisionThatReadTheSessionsAuthenticationIsForgotten(): void
    {
        $change = $this->sessionChange(FactorChangeMade::CONFIRMED);

        $this->recordDecision();

        $this->transition()->factorChanged($change);

        self::assertNull($this->lastDecision());
    }

    /**
     * A session that falls short of its requirement after the change returns
     * to pending, and the completion carries its new pending credential;
     * MFA's own assessment of the session plays no part.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatFallsShortReturnsToPendingWithANewCredential(): void
    {
        $change = $this->sessionChange(FactorChangeMade::CONFIRMED);

        $this->requireAFurtherFactor();

        $result = $this->transition()->factorChanged($change);

        self::assertTrue($result->isPending());
        self::assertNotNull($result->credential);
        self::assertSame($change->session, $result->pending?->id);
        self::assertSame(SessionStatus::PENDING, $this->sessionNamed($change->session)->getStatus());
    }

    /**
     * MFA's assessment that the session falls short does not stand in for
     * `laravel-authentication`'s judgement, which keeps it active.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfasAssessmentIsNotTheJudgement(): void
    {
        $made   = $this->sessionChange(FactorChangeMade::CONFIRMED);
        $change = new SessionChange($made->identity, $made->application, $made->session, $made->change, $made->factor, Requirement::strictest());

        self::assertTrue($this->transition()->factorChanged($change)->isActive());
    }

    /**
     * The sign-in MFA names is the session judged, never the guard's: a change
     * on another of the identity's sessions returns that one to pending and
     * leaves the guard's alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeOnAnotherSignInJudgesThatSignIn(): void
    {
        $person  = $this->createPerson();
        $other   = $this->signIn($person)->record;
        $current = $this->signInAndActOnSession($person);

        $this->requireAFurtherFactor();

        $change = new SessionChange($person, self::GUARD, $this->signInReference($other), FactorChangeMade::CONFIRMED, self::factorSummary(), null);

        self::assertTrue($this->transition()->factorChanged($change)->isPending());
        self::assertSame(SessionStatus::PENDING, $this->sessionNamed($this->signInReference($other))->getStatus());
        self::assertSame(SessionStatus::ACTIVE, $this->sessionNamed($this->signInReference($current))->getStatus());
    }

    /**
     * The sign-in MFA names is judged whatever the guard holds, as a change
     * made from a queued job or a console command is: a guard serving no one
     * still judges it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheNamedSignInIsJudgedWhateverTheGuardHolds(): void
    {
        $change = $this->sessionChange(FactorChangeMade::CONFIRMED);

        $this->stopActing(self::GUARD);
        $this->requireAFurtherFactor();

        self::assertTrue($this->transition()->factorChanged($change)->isPending());
        self::assertSame(SessionStatus::PENDING, $this->sessionNamed($change->session)->getStatus());
    }

    /**
     * A change on a sign-in that is no session of the identity's on the guard
     * (another identity's session, or a key no session holds) is refused inside
     * the change's transaction, which rolls back: no session is judged, and
     * what the change wrote is gone.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAChangeOnASignInThatIsNoSessionOfTheIdentitysIsRefusedAndRollsBack(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person   = $this->createPerson();
        $stranger = $this->signIn($this->createPerson())->record;

        $this->signInAndActOnSession($person);
        $this->requireAFurtherFactor();

        foreach ([$this->signInReference($stranger), '987654'] as $signIn) {

            $change    = new SessionChange($person, self::GUARD, $signIn, FactorChangeMade::CONFIRMED, self::factorSummary(), null);
            $exception = self::refusal(function () use ($person, $change): void {
                self::storage()->transaction(function () use ($person, $change): void {

                    $person->forceFill(['name' => 'Changed'])->save();

                    $this->transition()->factorChanged($change);
                });
            });

            self::assertSame(ReferenceKind::SESSION, $exception->kind);
            self::assertSame(self::GUARD, $exception->application);
            self::assertSame('Ada Lovelace', $person->refresh()->name);
        }

        self::assertSame(SessionStatus::ACTIVE, $this->sessionNamed($this->signInReference($stranger))->getStatus());
    }

    /**
     * An identity `laravel-authentication` does not sign in holds no session to
     * judge, so the change is refused before any guard is read.
     *
     * @return void
     */
    public function testAnIdentityThatIsNotLaravelAuthenticationsIsUnresolved(): void
    {
        $stranger = new class extends User implements MultiFactorAuthenticatable {
            use HasFactors;
        };

        $change = new SessionChange($stranger, 'not-a-guard', 'sign-in', FactorChangeMade::CONFIRMED, self::factorSummary(), null);

        self::assertSame(ReferenceKind::IDENTITY, self::refusal(fn (): mixed => $this->transition()->factorChanged($change))->kind);
    }

    /**
     * Confirming an enrolment on an active session through MFA, with the
     * factor-change adapters bound, judges the session last: its row is locked
     * after every row MFA locks, and the session that falls short returns to
     * pending, its credential reaching the confirmation.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testConfirmingAnEnrolmentJudgesTheSessionLastThroughMfa(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->bindTheFactorChangeAdapters();
        $this->nameTheSignIn($person, $session);
        $this->reauthenticate($person, $session);

        $start  = Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::totp('ada@example.test'));
        $factor = Factor::query()->sole();

        self::assertNotNull($start->grant);

        $this->requireAFurtherFactor();

        DB::enableQueryLog();

        $confirmation = Mfa::confirmEnrollment(self::servedCaller(), $start->grant, AuthenticatorApp::code($factor));

        $locks = array_values(array_filter(
            array_column(DB::getQueryLog(), 'query'),
            static fn (string $query): bool => str_contains($query, 'for update'),
        ));

        self::assertTrue($confirmation->isConfirmed());
        self::assertInstanceOf(FactorChangeResult::class, $confirmation->completion());
        self::assertTrue($confirmation->completion()->isPending());
        self::assertGreaterThan(1, count($locks));
        $last = end($locks);

        self::assertIsString($last);
        self::assertStringContainsString('authentication_sessions', $last);
        self::assertCount(1, array_filter($locks, static fn (string $query): bool => str_contains($query, 'authentication_sessions')));
    }

    /**
     * The transition under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\SessionTransition
     */
    #[\Override]
    protected function sessionTransition(): SessionTransition
    {
        return $this->transition();
    }

    /**
     * The change, made on an active session arranged afresh for it: a person
     * signed in on the guard, acting on the session, and its key as MFA names
     * the sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChangeMade  $change
     * @return \SineMacula\Laravel\Mfa\Requirements\SessionChange
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function sessionChange(FactorChangeMade $change): SessionChange
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        return new SessionChange($person, self::GUARD, $this->signInReference($session), $change, self::factorSummary(), null);
    }

    /**
     * The session stored under the key, as stored now.
     *
     * @param  string  $key
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function sessionNamed(string $key): EloquentSession&Model
    {
        $session = Session::query()->findOrFail($key);

        self::assertInstanceOf(EloquentSession::class, $session);

        return $session;
    }

    /**
     * Assert the call is refused as an unresolved reference, and return the
     * refusal.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function refusal(\Closure $call): UnresolvedReferenceException
    {
        try {
            $call();
        } catch (UnresolvedReferenceException $exception) {
            return $exception;
        }

        self::fail('The change was judged without a session to judge.');
    }

    /**
     * Resolve the transition under test from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\SessionTransitionAdapter
     */
    private function transition(): SessionTransitionAdapter
    {
        $transition = $this->app?->make(SessionTransitionAdapter::class);

        self::assertInstanceOf(SessionTransitionAdapter::class, $transition);

        return $transition;
    }
}
