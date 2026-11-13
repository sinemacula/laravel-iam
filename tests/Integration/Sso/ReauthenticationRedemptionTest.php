<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason as AuthenticationFailure;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\External\NoExternalLinks;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\ExternalReauthenticationRefusedException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Iam\Sso\ExternalResults;
use SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption;
use SineMacula\Laravel\Iam\Sso\RenewalRecorder;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\ReauthenticationCompleted;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RecordsRequirementDecisions;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\Handoff;
use Tests\Fixtures\Sso\Redemptions;
use Tests\Fixtures\Sso\ScriptedReauthenticationSessions;
use Tests\TestCase;

/**
 * Integration tests for redeeming a `reauthenticate` handoff code and renewing
 * its session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReauthenticationRedemption::class)]
#[CoversClass(ExternalResults::class)]
final class ReauthenticationRedemptionTest extends TestCase
{
    use MigratesSso, RecordsRequirementDecisions, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string What a renewal asked for while no redemption is open to write it is. */
    private const string NO_REDEMPTION = 'SSO asked for a renewal no redemption would write: a re-authentication is redeemed through Iam::reauthentications().';

    /** @var string A verifier of the right shape that answers no challenge. */
    private const string WRONG_VERIFIER = 'not-the-verifier-the-client-kept-0123456789';

    /** @var \ArrayObject<int, object> What SSO and `laravel-authentication` reported, in order. */
    private \ArrayObject $reported;

    /** @var \Tests\Fixtures\Models\Person The person signed in through SSO. */
    private Person $person;

    /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession The session SSO signed the person in to. */
    private EloquentSession&Model $session;

    /**
     * Arrange SSO, sign the person in through it, and record what each
     * redemption reports.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->person = $this->createPerson();

        $this->linkThroughFlow($this->person);

        $handoff = $this->handoff();
        $signIn  = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $signIn);
        self::assertNotNull($signIn->session);

        $this->session = $signIn->session->record;

        $reported       = new \ArrayObject;
        $this->reported = $reported;

        Event::listen([FlowFailed::class, HandoffRedeemed::class, ReauthenticationCompleted::class, Reauthenticated::class], static function (object $event) use ($reported): void {
            $reported->append($event);
        });

        $this->travel(30)->seconds();
    }

    /**
     * The renewal is written once for the session the code names.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheRenewalIsWrittenOnceForTheRecordedSession(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $refreshKey = $this->session->fresh()?->getRefreshKey();
        $provenance = (array) DB::table('authentication_provenance')->first();
        $sessions   = $this->recordingSessions(ScriptedReauthenticationSessions::AS_THE_ADAPTER);
        $answer     = $this->redeem($this->reauthenticationHandoff());

        self::assertInstanceOf(AccessTokenResult::class, $answer);
        self::assertTrue($answer->isIssued());
        self::assertSame($this->session->getKey(), $answer->session?->getKey());
        self::assertSame(now()->getTimestamp(), self::authTimeOf($answer));
        self::assertSame(1, $sessions->renewals);
        self::assertSame($refreshKey, $this->session->fresh()?->getRefreshKey());
        self::assertSame($provenance, (array) DB::table('authentication_provenance')->first());
        self::assertSame(1, DB::table('authentication_sessions')->count());
        self::assertSame([HandoffRedeemed::class, ReauthenticationCompleted::class, Reauthenticated::class], $this->reportedEvents());

        $completed = $this->reported[1];

        self::assertInstanceOf(ReauthenticationCompleted::class, $completed);
        self::assertSame([self::CLIENT_IP, self::CLIENT_AGENT], [$completed->context->ip, $completed->context->userAgent]);
        self::assertFalse($this->app?->make(RenewalRecorder::class)->isHolding());
    }

    /**
     * An older provider time leaves the session's own `auth_time`.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnOlderProviderTimeLeavesTheSessionsOwn(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $handoff = $this->reauthenticationHandoff();

        $this->travel(20)->seconds();

        $current = $this->session->fresh() ?? self::fail('The session is gone.');
        $renewed = $this->sessions()->reauthenticate($current, 'password', ['email' => $this->person->email, 'password' => self::PASSWORD], self::client());

        self::assertTrue($renewed->isIssued());

        $answer = $this->redeem($handoff);

        self::assertInstanceOf(AccessTokenResult::class, $answer);
        self::assertSame(now()->getTimestamp(), self::authTimeOf($answer));
        self::assertSame(self::authTimeOf($renewed), self::authTimeOf($answer));
    }

    /**
     * A refusal by SSO commits and spends the code.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusalBySsoCommitsAndSpendsTheCode(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $handoff  = $this->reauthenticationHandoff();
        $refused  = $this->redeem(new Handoff($handoff->code, self::WRONG_VERIFIER, $handoff->reference));
        $replayed = $this->redeem($handoff);

        self::assertInstanceOf(RedemptionResult::class, $refused);
        self::assertSame(FailureReason::VERIFIER_MISMATCH, $refused->reason);
        self::assertInstanceOf(RedemptionResult::class, $replayed);
        self::assertSame(FailureReason::REPLAYED, $replayed->reason);
        self::assertSame([FlowFailed::class, FlowFailed::class], $this->reportedEvents());
    }

    /**
     * A failed token result rolls back and leaves the code unspent.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAFailedTokenResultRollsBackAndLeavesTheCodeUnspent(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $handoff = $this->reauthenticationHandoff();
        $links   = $this->app?->make(ExternalIdentityLinks::class);

        $this->app?->instance(ExternalIdentityLinks::class, new NoExternalLinks);

        $refusal = self::thrownBy(fn (): mixed => $this->redeem($handoff));

        self::assertInstanceOf(ExternalReauthenticationRefusedException::class, $refusal);
        self::assertSame(AuthenticationFailure::EXTERNAL_RESULT_UNLINKED, $refusal->result->reason);
        self::assertSame([], $this->reportedEvents());

        $this->app?->instance(ExternalIdentityLinks::class, $links);

        $answer = $this->redeem($handoff);

        self::assertInstanceOf(AccessTokenResult::class, $answer);
        self::assertTrue($answer->isIssued());
    }

    /**
     * A renewal forgets the request's authorisation decisions.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARenewalForgetsTheRequestsDecisions(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $handoff = $this->reauthenticationHandoff();

        $this->recordDecision();

        self::assertInstanceOf(AccessTokenResult::class, $this->redeem($handoff));
        self::assertNull($this->lastDecision());
    }

    /**
     * A refusal by SSO renews nothing, so the request's decisions are kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalBySsoKeepsTheRequestsDecisions(): void
    {
        $handoff  = $this->reauthenticationHandoff();
        $decision = $this->recordDecision();

        self::assertInstanceOf(RedemptionResult::class, $this->redeem(new Handoff($handoff->code, self::WRONG_VERIFIER, $handoff->reference)));
        self::assertSame($decision, $this->lastDecision());
    }

    /**
     * Rows of a broken renewal and the `LogicException` it is.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideBrokenRenewals(): iterable
    {
        yield 'no renewal recorded' => [ScriptedReauthenticationSessions::RECORD_NOTHING, 'SSO admitted a re-authentication without asking for its renewal.'];

        yield 'another session renewed' => [
            ScriptedReauthenticationSessions::RECORD_ANOTHER_SESSION,
            'A re-authentication renews the session its code names: SSO asked to renew another.',
        ];

        yield 'a renewal SSO refused' => [
            ScriptedReauthenticationSessions::RECORD_AND_REFUSE,
            'A re-authentication commits with its one renewal written: a renewal SSO asked for is still recorded.',
        ];
    }

    /**
     * A broken renewal is a `LogicException` that rolls back.
     *
     * @param  string  $script
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideBrokenRenewals')]
    public function testABrokenRenewalIsALogicExceptionThatRollsBack(string $script, string $message): void
    {
        $handoff = $this->reauthenticationHandoff();

        $this->recordingSessions($script);

        $broken = self::thrownBy(fn (): mixed => $this->redeem($handoff));

        self::assertInstanceOf(\LogicException::class, $broken);
        self::assertSame($message, $broken->getMessage());
        self::assertSame([], $this->reportedEvents());
        self::assertFalse($this->app?->make(RenewalRecorder::class)->isHolding());

        $this->recordingSessions(ScriptedReauthenticationSessions::AS_THE_ADAPTER);

        self::assertInstanceOf(AccessTokenResult::class, $this->redeem($handoff));
    }

    /**
     * An application that is no session guard throws before the code is
     * touched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationThatIsNoSessionGuardThrowsBeforeTheCodeIsTouched(): void
    {
        $handoff    = $this->reauthenticationHandoff();
        $unresolved = self::thrownBy(fn (): mixed => Iam::reauthentications()->redeem('web', $this->connectionId, $handoff->code, $handoff->verifier, self::client()));

        self::assertInstanceOf(UnresolvedReferenceException::class, $unresolved);
        self::assertSame(ReferenceKind::GUARD, $unresolved->kind);
        self::assertSame([], $this->reportedEvents());
        self::assertInstanceOf(AccessTokenResult::class, $this->redeem($handoff));
    }

    /**
     * The admitted redemption and renewal are forgotten as the redemption
     * starts and ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRecordsAreTheRedemptionsAlone(): void
    {
        $admitted = $this->app?->make(AdmittedRedemptions::class);
        $recorder = $this->app?->make(RenewalRecorder::class);

        self::assertInstanceOf(AdmittedRedemptions::class, $admitted);
        self::assertInstanceOf(RenewalRecorder::class, $recorder);

        $handoff = $this->reauthenticationHandoff();

        $admitted->record(Redemptions::signIn());
        $recorder->open();
        $recorder->record(Redemptions::identity(), Redemptions::SESSION, now()->toImmutable(), null);

        self::assertInstanceOf(AccessTokenResult::class, $this->redeem($handoff));
        self::assertNull($admitted->matching(Redemptions::CONNECTION, Redemptions::ISSUER, Redemptions::SUBJECT));
        self::assertNull($admitted->matching($this->connectionId, (string) $this->provider?->issuer, 'fake-subject'));
        self::assertFalse($recorder->isHolding());
    }

    /**
     * A code admitted outside the redemption renews nothing and stays unspent.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testACodeAdmittedOutsideItsRedemptionRenewsNothingAndStaysUnspent(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $app        = $this->app ?? self::fail('The application has not booted.');
        $handoff    = $this->reauthenticationHandoff();
        $before     = (array) DB::table('authentication_sessions')->first();
        $redemption = $app->make(HandoffRedemption::class);
        $refused    = self::thrownBy(fn (): mixed => DB::transaction(fn (): RedemptionResult => $redemption->admit(
            Purpose::REAUTHENTICATE,
            self::GUARD,
            $this->connectionId,
            $handoff->code,
            $handoff->verifier,
            self::ssoClient(),
        )));

        self::assertInstanceOf(\LogicException::class, $refused);
        self::assertSame(self::NO_REDEMPTION, $refused->getMessage());
        self::assertSame(0, DB::transactionLevel());
        self::assertSame([], $this->reportedEvents());
        self::assertSame($before, (array) DB::table('authentication_sessions')->first());
        self::assertFalse($app->make(RenewalRecorder::class)->isHolding());

        $answer = $this->redeem($handoff);

        self::assertInstanceOf(AccessTokenResult::class, $answer);
        self::assertTrue($answer->isIssued());
    }

    /**
     * A job's redemption reports no IP address or user agent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJobsRedemptionReportsNoClient(): void
    {
        $handoff = $this->reauthenticationHandoff();
        $answer  = Iam::reauthentications()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new ClientContext(null, null));

        self::assertInstanceOf(AccessTokenResult::class, $answer);

        $completed = $this->reported[1];

        self::assertInstanceOf(ReauthenticationCompleted::class, $completed);
        self::assertSame([null, null], [$completed->context->ip, $completed->context->userAgent]);
    }

    /**
     * A `reauthenticate` handoff for the person's session.
     *
     * @return \Tests\Fixtures\Sso\Handoff
     *
     * @throws \Random\RandomException
     */
    private function reauthenticationHandoff(): Handoff
    {
        return $this->handoff(Purpose::REAUTHENTICATE, $this->person, self::keyOf($this->session));
    }

    /**
     * Redeem the `reauthenticate` handoff for the tests' client.
     *
     * @param  \Tests\Fixtures\Sso\Handoff  $handoff
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function redeem(Handoff $handoff): AccessTokenResult|RedemptionResult
    {
        return Iam::reauthentications()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client());
    }

    /**
     * Bind and answer the scripted reauthentication sessions.
     *
     * @param  string  $script
     * @return \Tests\Fixtures\Sso\ScriptedReauthenticationSessions
     */
    private function recordingSessions(string $script): ScriptedReauthenticationSessions
    {
        $app      = $this->app ?? self::fail('The application has not booted.');
        $sessions = new ScriptedReauthenticationSessions($app, $script);

        $app->instance(ReauthenticationSessions::class, $sessions);

        return $sessions;
    }

    /**
     * The `auth_time` the access token carries.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult  $result
     * @return mixed
     */
    private static function authTimeOf(AccessTokenResult $result): mixed
    {
        $parts   = explode('.', (string) $result->accessToken?->reveal());
        $payload = json_decode((string) base64_decode(strtr($parts[1] ?? '', '-_', '+/'), true), true);

        return is_array($payload) ? $payload['auth_time'] ?? null : null;
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

    /**
     * The class of each event reported, in order.
     *
     * @return list<class-string>
     */
    private function reportedEvents(): array
    {
        return array_values(array_map(static fn (object $event): string => $event::class, $this->reported->getArrayCopy()));
    }
}
