<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Auth\GenericUser;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Codes\FactorCodeCheck;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding as AuthenticationBinding;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\FactorCodeCallers;
use SineMacula\Laravel\Iam\Mfa\FactorCodeCountersAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\LockoutApplied;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ChallengeCountersTests;
use Tests\Concerns\BindsStrayRequests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Codes\Concerns\ArrangesDeliveredFactors;
use Tests\Fixtures\Mfa\Codes\Concerns\DeliversFactorCodes;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authentication`'s factor code counters over
 * MFA's challenge counters (IAM-3.9): `laravel-authentication`, the owner of
 * the challenges, asks MFA before each delivery and each check and tells it
 * each attempt it counts, inside its own transaction, so a wrong code counts
 * against the factor and the identity once, and rolls back with whatever the
 * transaction was part of.
 *
 * The challenges are `laravel-authentication`'s own, sent and checked through
 * `Auth::codes()` as any owner's path would, with every adapter of this
 * package's bound and real sessions signed in with a password, so MFA reads the
 * session's first factor from it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorCodeCountersAdapter::class)]
#[CoversClass(CodeTranslator::class)]
final class FactorCodeCountersAdapterTest extends TestCase
{
    use ArrangesDeliveredFactors, BindsStrayRequests, ChallengeCountersTests, DeliversFactorCodes, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string A number no factor of the person's sends to. */
    private const string OTHER_PHONE = '+447700900999';

    /** @var string What the tests roll their own transaction back with. */
    private const string ROLLED_BACK = 'The transaction rolls back.';

    /** @var ?\Tests\Fixtures\Models\Person The person whose challenges are counted. */
    private ?Person $person = null;

    /** @var ?(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession) The session the challenges are bound to. */
    private (EloquentSession&Model)|null $session = null;

    /** @var ?\SineMacula\Laravel\Mfa\Models\Factor The factor whose challenges are counted. */
    private ?FactorModel $factor = null;

    /** @var ?array{0: string, 1: string} The live challenge and the code delivered for it. */
    private ?array $challenge = null;

    /** @var list<array{0: int|string|null, 1: int|string|null}> The IP address and user agent of each lockout MFA reported, in order. */
    private array $lockouts = [];

    /**
     * Fake the delivery of factor codes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fakeFactorCodeDelivery();
    }

    /**
     * A matching code is verified once MFA admits it, and its success resets
     * the failures the factor had in a row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMatchingCodeIsVerifiedAndResetsTheFactorsFailures(): void
    {
        $this->failChallenge();

        self::assertSame(1, $this->failures());

        [$challenge, $code] = $this->liveChallenge();

        $check = $this->codes()->verifyFactorCode($this->factorCodeBinding(), $challenge, $code, self::client());

        self::assertSame(FactorCodeOutcome::VERIFIED, $check->outcome);
        self::assertSame(0, $this->failures());
    }

    /**
     * A wrong code that locks nothing is invalid and counted, and carries no
     * lock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongCodeThatLocksNothingCarriesNoLock(): void
    {
        $check = $this->checkWrongly();

        self::assertSame(FactorCodeOutcome::INVALID, $check->outcome);
        self::assertNull($check->lockedUntil);
        self::assertSame(1, $this->failures());
    }

    /**
     * A wrong code that reaches the factor's limit is invalid and counted, and
     * carries the lock it caused, until the lock ends: the factor is locked
     * from then on, so the next code is refused as locked until then.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongCodeThatReachesTheFactorsLimitLocksIt(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        $check = $this->checkWrongly();

        self::assertSame(FactorCodeOutcome::INVALID, $check->outcome);
        self::assertNotNull($check->lockedUntil);
        self::assertTrue($check->lockedUntil->isFuture());
        self::assertSame(1, $this->failures());

        $request = $this->codes()->sendFactorCode($this->factorCodeBinding(), self::client());

        self::assertSame(CodeRequestStatus::LOCKED, $request->status);
        self::assertNotNull($request->lockedUntil);
        self::assertTrue($check->lockedUntil->equalTo($request->lockedUntil));
    }

    /**
     * A wrong code that reaches the identity's limit, though not the factor's,
     * is invalid and counted, and carries the identity's lock it caused, until
     * that ends: the next code is refused as locked until then.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongCodeThatReachesTheIdentitysLimitCarriesItsLock(): void
    {
        config()->set('mfa.attempts.identity_limit', 1);

        $check = $this->checkWrongly();

        self::assertSame(FactorCodeOutcome::INVALID, $check->outcome);
        self::assertNotNull($check->lockedUntil);
        self::assertTrue($check->lockedUntil->isFuture());
        self::assertNull(FactorModel::query()->whereKey($this->countedFactor()->getKey())->sole()->getLockedUntil());

        $request = $this->codes()->sendFactorCode($this->factorCodeBinding(), self::client());

        self::assertSame(CodeRequestStatus::LOCKED, $request->status);
        self::assertNotNull($request->lockedUntil);
        self::assertTrue($check->lockedUntil->equalTo($request->lockedUntil));
    }

    /**
     * A factor MFA has locked is sent no code, and locked until the lock ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockedFactorIsLockedUntilTheLockEnds(): void
    {
        $factor = $this->countedFactor();
        $until  = CarbonImmutable::now()->startOfSecond()->addMinutes(10);

        FactorModel::query()->whereKey($factor->getKey())->update([$factor->getLockedUntilName() => $until]);

        $request = $this->codes()->sendFactorCode($this->factorCodeBinding(), self::client());

        self::assertSame(CodeRequestStatus::LOCKED, $request->status);
        self::assertEquals($until, $request->lockedUntil);
    }

    /**
     * An identity `laravel-authentication` has deactivated is inactive to MFA
     * too, through the active state adapter: once deactivated, no code is sent
     * for its factor and the code it was sent before is never checked, each
     * refused as `identity_inactive`, though no request's bearer token is
     * refused first, as a queued job's or a console's call to the factor codes
     * runs, at either isolation level.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testADeactivatedIdentitysFactorCodesAreRefusedAsInactive(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$challenge, $code] = $this->liveChallenge();

        $person = $this->person();
        $issued = OneTimeCode::query()->count();

        $person->forceFill(['is_active' => false])->save();

        $request = $this->codes()->sendFactorCode($this->factorCodeBinding(), self::client());
        $check   = $this->codes()->verifyFactorCode($this->factorCodeBinding(), $challenge, $code, self::client());

        self::assertFalse($this->app?->make(ActiveStateResolver::class)->isActive($person));
        self::assertSame(CodeRequestStatus::REFUSED, $request->status);
        self::assertSame(FactorCodeRefusal::IDENTITY_INACTIVE, $request->refusal);
        self::assertSame(FactorCodeOutcome::REFUSED, $check->outcome);
        self::assertSame(FactorCodeRefusal::IDENTITY_INACTIVE, $check->refusal);
        self::assertSame($issued, OneTimeCode::query()->count());
        self::assertSame(0, $this->failures());

        $person->forceFill(['is_active' => true])->save();

        self::assertTrue($this->codes()->verifyFactorCode($this->factorCodeBinding(), $challenge, $code, self::client())->isVerified());
    }

    /**
     * A factor that is not the identity's, and one that does not exist, are not
     * found: no code is issued for either.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorThatIsNotTheIdentitysIsNotFound(): void
    {
        $this->countedFactor();

        $issued = OneTimeCode::query()->count();
        $others = $this->deliveredFactor($this->createPerson());

        foreach ([$others->id, 'unknown-factor'] as $factor) {

            $request = $this->codes()->sendFactorCode($this->factorCodeBinding(factor: $factor), self::client());

            self::assertSame(CodeRequestStatus::REFUSED, $request->status);
            self::assertSame(FactorCodeRefusal::NOT_FOUND, $request->refusal);
        }

        self::assertSame($issued, OneTimeCode::query()->count());
    }

    /**
     * A binding that names the factor on another channel than its own, or to
     * another destination, is not found, so no code for the factor goes
     * anywhere but to the factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABindingOnAnotherChannelThanTheFactorsIsNotFound(): void
    {
        $this->countedFactor();

        foreach ([new Channel(ChannelKind::SMS, self::OTHER_PHONE), new Channel(ChannelKind::EMAIL, self::DELIVERED_PHONE)] as $channel) {

            $request = $this->codes()->sendFactorCode($this->factorCodeBinding(channel: $channel), self::client());

            self::assertSame(CodeRequestStatus::REFUSED, $request->status);
            self::assertSame(FactorCodeRefusal::NOT_FOUND, $request->refusal);
        }

        self::assertSame(0, $this->queuedDeliveries());
    }

    /**
     * A binding naming no session MFA could refer back to cannot be resolved,
     * and throws inside `laravel-authentication`'s transaction: no new code is
     * kept and none is delivered, at either isolation level.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAnUnresolvableSessionThrowsInsideAuthenticationsTransaction(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $this->countedFactor();

        $refusal = null;

        try {
            $this->codes()->sendFactorCode($this->factorCodeBinding(session: 1.5), self::client());
        } catch (UnresolvedReferenceException $exception) {
            $refusal = $exception;
        }

        self::assertInstanceOf(UnresolvedReferenceException::class, $refusal);
        self::assertSame(ReferenceKind::SESSION, $refusal->kind);
        self::assertSame(1, OneTimeCode::query()->count(), 'Only the code delivered before is kept.');
        self::assertSame(0, $this->queuedDeliveries());
    }

    /**
     * An attempt counted inside the caller's transaction rolls back with it:
     * the factor's failure and `laravel-authentication`'s attempt are both
     * undone, at either isolation level.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testACountedAttemptRollsBackWithTheCallersTransaction(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$challenge] = $this->liveChallenge();

        try {
            DB::connection(StorageConnection::name())->transaction(function (): never {

                self::assertSame(FactorCodeOutcome::INVALID, $this->checkWrongly()->outcome);
                self::assertSame(1, $this->failures());

                throw new \RuntimeException(self::ROLLED_BACK);
            });
        } catch (\RuntimeException $exception) {
            self::assertSame(self::ROLLED_BACK, $exception->getMessage());
        }

        self::assertSame(0, $this->failures());
        $attempts = OneTimeCode::query()->where('challenge_id', $challenge)->value('attempts');

        self::assertTrue(is_numeric($attempts));
        self::assertSame(0, (int) $attempts);
    }

    /**
     * An identity MFA holds no factors for cannot be resolved, so neither an
     * admission nor a report is answered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityMfaHoldsNoFactorsForThrows(): void
    {
        $identity = new class (['id' => 7]) extends GenericUser implements Identity {};
        $proof    = new AuthenticationBinding($identity, self::GUARD, 'session-1', AuthenticationPurpose::STEP_UP);
        $binding  = new FactorCodeBinding($proof, 'factor-1', new Channel(ChannelKind::SMS, self::DELIVERED_PHONE));
        $counters = $this->app?->make(FactorCodeCountersAdapter::class) ?? self::fail('The application has not booted.');

        foreach ([static fn (): mixed => $counters->admit($binding), static fn (): mixed => $counters->report($binding, 'challenge-1', false)] as $call) {

            $refusal = null;

            try {
                $call();
            } catch (UnresolvedReferenceException $exception) {
                $refusal = $exception;
            }

            self::assertInstanceOf(UnresolvedReferenceException::class, $refusal);
            self::assertSame(ReferenceKind::IDENTITY, $refusal->kind);
        }
    }

    /**
     * An attempt reported for a factor that is no longer the identity's counts
     * nothing, and is refused as not found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttemptAtAFactorNoLongerStoredIsNotFound(): void
    {
        $this->countedFactor();

        $counters = $this->app?->make(FactorCodeCountersAdapter::class) ?? self::fail('The application has not booted.');
        $binding  = $this->factorCodeBinding(factor: 'removed-factor');
        $answer   = DB::connection(StorageConnection::name())->transaction(static fn (): mixed => $counters->report($binding, 'challenge-1', true));

        self::assertSame(FactorCodeRefusal::NOT_FOUND, $answer->refusal);
        self::assertSame(0, $this->failures());
    }

    /**
     * The counters judge the caller MFA's challenge gateway kept beside the
     * binding, never the binding's identity in its place: a caller kept as
     * nobody is refused by MFA's counters, for an admission and for an attempt
     * alike, though the binding's identity has a factor to count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallerKeptBesideTheBindingIsJudged(): void
    {
        $this->countedFactor();

        $app      = $this->app ?? self::fail('The application has not booted.');
        $counters = $app->make(FactorCodeCountersAdapter::class);
        $binding  = $this->factorCodeBinding();

        $app->make(FactorCodeCallers::class)->hold($binding, CallerContext::nobody(self::GUARD));

        foreach ([static fn (): mixed => $counters->admit($binding), static fn (): mixed => $counters->report($binding, 'challenge-1', true)] as $call) {
            try {
                DB::connection(StorageConnection::name())->transaction($call);

                self::fail('A caller that is nobody was counted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('Challenge counters are kept for an identity, and the caller is nobody.', $exception->getMessage());
            }
        }

        self::assertSame(0, $this->failures());
    }

    /**
     * The caller kept beside the binding is the one an attempt is counted for:
     * a wrong code that locks the factor is reported by MFA for that caller's
     * client, though the container holds a request from another client.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttemptIsCountedForTheKeptCallersClient(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        [$challenge, $code] = $this->liveChallenge();

        $app     = $this->app ?? self::fail('The application has not booted.');
        $binding = $app->make(FactorCodeCallers::class)->hold($this->factorCodeBinding(), self::callerOf($this->person()));

        $this->recordLockouts();

        $this->bindStrayRequest();

        self::assertSame(FactorCodeOutcome::INVALID, $this->codes()->verifyFactorCode($binding, $challenge, self::wrong($code), self::client())->outcome);
        self::assertSame(1, $this->failures());
        self::assertSame([[self::CLIENT_IP, self::CLIENT_AGENT]], $this->lockouts);
    }

    /**
     * A binding the challenge gateway did not make is judged as its identity's
     * own on its application, from the binding alone: though the container
     * holds a request from another client carrying a pending sign-in's
     * credential of the identity's, the binding's active session is the one
     * judged, and the attempt is counted for no client known, never the
     * request's. (`laravel-authentication` hands the counters no client, so MFA
     * names none; member gap.).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABindingTheGatewayDidNotMakeIsJudgedFromTheBindingAlone(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        $this->liveChallenge();

        $pending = $this->attemptSignIn($this->person());

        self::assertTrue($pending->isPending(), (string) $pending->reason?->value);
        self::assertNotNull($pending->credential);

        $this->recordLockouts();
        $this->bindStrayRequest(['pending_credential' => $pending->credential->reveal()]);

        self::assertSame(FactorCodeOutcome::INVALID, $this->checkWrongly()->outcome);
        self::assertSame(1, $this->failures());
        self::assertSame([[null, null]], $this->lockouts);
    }

    /**
     * The person whose challenges are counted, signed in on the guard and
     * acting on their session.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function countedIdentity(): MultiFactorAuthenticatable
    {
        if ($this->person === null) {
            $this->person  = $this->createPerson();
            $this->session = $this->signInAndActOnSession($this->person);
        }

        return $this->person;
    }

    /**
     * The person's confirmed SMS factor, with a code already delivered for it,
     * so a wrong code is always one other than the code sent.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function countedFactor(): EloquentFactor&Model
    {
        if ($this->factor === null) {
            $this->factor = $this->deliveredFactor($this->person());

            $this->liveChallenge();
        }

        return $this->factor;
    }

    /**
     * A pending SMS factor of the person's, with no enrolment under way.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function pendingFactor(): EloquentFactor&Model
    {
        return $this->pendingDeliveredFactor($this->person(), 'sms', self::OTHER_PHONE);
    }

    /**
     * A step-up of the person's current session.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function countedBinding(): ProofBinding
    {
        $owner = IdentityReference::of($this->person());

        return new ProofBinding($owner->type, $owner->key, self::GUARD, $this->sessionReference(), Purpose::STEP_UP);
    }

    /**
     * Check a wrong code against the live challenge through
     * `laravel-authentication`, as a person submitting it would.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function failChallenge(): void
    {
        $this->checkWrongly();
    }

    /**
     * Check the right code against the live challenge through
     * `laravel-authentication`, using it up, and return what checks it again.
     *
     * @return \Closure(): void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function consumeChallenge(): \Closure
    {
        [$challenge, $code] = $this->liveChallenge();

        $binding = $this->factorCodeBinding();
        $codes   = $this->codes();

        self::assertTrue($codes->verifyFactorCode($binding, $challenge, $code, self::client())->isVerified());

        $this->challenge = null;

        return static function () use ($codes, $binding, $challenge, $code): void {
            $codes->verifyFactorCode($binding, $challenge, $code, self::client());
        };
    }

    /**
     * Ask this package's counters whether they admit a challenge of the factor
     * under the binding, translated to the factor code binding
     * `laravel-authentication` asks them under.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function isChallengeAdmitted(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding): bool
    {
        return $this->adapter()->admit($this->codeBindingOf($identity, $factor, $binding))->isAdmitted();
    }

    /**
     * Report a challenge's outcome through this package's counters, under the
     * factor code binding `laravel-authentication` reports under.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  bool  $passed
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function reportChallenge(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding, bool $passed): void
    {
        $this->adapter()->report($this->codeBindingOf($identity, $factor, $binding), 'challenge-1', $passed);
    }

    /**
     * Bind the application's gateways before the application boots.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->defineFactorCodes($app);
    }

    /**
     * Check a wrong code against the live challenge through
     * `laravel-authentication`.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeCheck
     *
     * @throws \Throwable
     */
    private function checkWrongly(): FactorCodeCheck
    {
        [$challenge, $code] = $this->liveChallenge();

        return $this->codes()->verifyFactorCode($this->factorCodeBinding(), $challenge, self::wrong($code), self::client());
    }

    /**
     * From now on, record the IP address and user agent of each lockout MFA
     * reports.
     *
     * @return void
     */
    private function recordLockouts(): void
    {
        Event::listen(LockoutApplied::class, function (LockoutApplied $event): void {
            $this->lockouts[] = [$event->context['ip'] ?? null, $event->context['user_agent'] ?? null];
        });
    }

    /**
     * A code of the same length that is not the one given.
     *
     * @param  string  $code
     * @return string
     */
    private static function wrong(#[\SensitiveParameter] string $code): string
    {
        $zeros = str_repeat('0', strlen($code));

        return $code === $zeros ? str_repeat('1', strlen($code)) : $zeros;
    }

    /**
     * The live challenge and the code delivered for it: one is sent and
     * delivered when there is none, or the last was used up.
     *
     * @return array{0: string, 1: string}
     *
     * @throws \Throwable
     */
    private function liveChallenge(): array
    {
        if ($this->challenge !== null) {
            return $this->challenge;
        }

        $request = $this->codes()->sendFactorCode($this->factorCodeBinding(), self::client());

        self::assertSame(CodeRequestStatus::SENT, $request->status, (string) $request->refusal?->value);

        return $this->challenge = [(string) $request->challengeId, $this->deliveredCodeTo(self::DELIVERED_PHONE)];
    }

    /**
     * A stored person of the same type under the key given, held as a string
     * so a key no integer can hold (the kit's other identity) is kept as it is.
     *
     * @param  string  $key
     * @return \Tests\Fixtures\Models\Person
     */
    private static function personKeyed(string $key): Person
    {
        $person = (new Person)->setKeyType('string')->setIncrementing(false);

        $person->forceFill([$person->getKeyName() => $key])->exists = true;

        return $person;
    }

    /**
     * This package's challenge counters.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\FactorCodeCountersAdapter
     */
    private function adapter(): FactorCodeCountersAdapter
    {
        return $this->app?->make(FactorCodeCountersAdapter::class) ?? self::fail('The application has not booted.');
    }

    /**
     * The factor code binding `laravel-authentication` asks the counters
     * under for MFA's binding: the identity the binding names (the person, or
     * another identity of the same type and the key the binding gives), and
     * the factor's SMS channel.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     *
     * @throws \InvalidArgumentException
     */
    private function codeBindingOf(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding): FactorCodeBinding
    {
        self::assertInstanceOf(Person::class, $identity);

        $named = IdentityReference::of($identity)->key === $binding->identityKey ? $identity : self::personKeyed($binding->identityKey);

        return $this->app?->make(CodeTranslator::class)->toAuthentication($named, $factor, MfaChannelKind::SMS, $binding) ?? self::fail('The application has not booted.');
    }

    /**
     * The factor code binding of the person's step-up on their session, for the
     * factor and on the channel given, or the counted factor's own.
     *
     * @param  ?string  $factor
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @param  mixed  $session
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     *
     * @throws \Throwable
     */
    private function factorCodeBinding(?string $factor = null, ?Channel $channel = null, mixed $session = null): FactorCodeBinding
    {
        $counted = $this->countedFactor();
        $proof   = new AuthenticationBinding($this->person(), self::GUARD, $session ?? $this->sessionReference(), AuthenticationPurpose::STEP_UP);

        return new FactorCodeBinding($proof, $factor ?? CodeTranslator::reference($counted), $channel ?? new Channel(ChannelKind::SMS, self::DELIVERED_PHONE));
    }

    /**
     * `laravel-authentication`'s code service for the guard.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\CodeService
     */
    private function codes(): CodeService
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        return $auth->codes(self::GUARD);
    }

    /**
     * The person whose challenges are counted.
     *
     * @return \Tests\Fixtures\Models\Person
     *
     * @throws \Throwable
     */
    private function person(): Person
    {
        $person = $this->countedIdentity();

        self::assertInstanceOf(Person::class, $person);

        return $person;
    }

    /**
     * The reference MFA names the person's session by.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function sessionReference(): string
    {
        $this->person();

        return $this->signInReference($this->session ?? self::fail('The person has not signed in.'));
    }

    /**
     * The counted factor's failures in a row, as stored.
     *
     * @return int
     */
    private function failures(): int
    {
        $factor = $this->factor ?? self::fail('No factor has been arranged.');

        return FactorModel::query()->whereKey($factor->getKey())->sole()->getConsecutiveFailures();
    }
}
