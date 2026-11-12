<?php

declare(strict_types = 1);

namespace Tests\Integration\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind as AuthenticationProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Testing\CallerCompletion;
use SineMacula\Laravel\Iam\Testing\CallerSignIn;
use SineMacula\Laravel\Iam\Testing\Concerns\InteractsWithIam;
use SineMacula\Laravel\Iam\Testing\FixtureFactors;
use SineMacula\Laravel\Iam\Testing\VerifiedSession;
use SineMacula\Laravel\Iam\Testing\VerifiedSignInRecorderAdapter;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Concerns\InteractsWithMfa;
use SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder;
use SineMacula\Laravel\Mfa\Testing\LevelEvidence;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Testing\LeveledCombinationPolicy;
use Tests\TestCase;

/**
 * MFA's `actingAsVerified()` through this package's recorder.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerifiedSignInRecorderAdapter::class)]
#[CoversClass(FixtureFactors::class)]
#[CoversClass(VerifiedSession::class)]
#[CoversClass(CallerCompletion::class)]
#[CoversClass(CallerSignIn::class)]
#[CoversClass(MfaSeams::class)]
final class VerifiedSignInRecorderAdapterTest extends TestCase
{
    use InteractsWithIam, InteractsWithMfa, MigratesMembers, SignsInPeople;

    /** @var string The route that answers the level the `mfa` context namespace reads. */
    private const string CONTEXT_ROUTE = '/verified/context';

    /** @var string A guard people may not sign in on with a password. */
    private const string CODE_GUARD = 'codes';

    /** @var string What a proof bound to no current sign-in of its identity is refused with. */
    private const string UNBOUND = 'The proof is not bound to its identity\'s current sign-in, so it cannot be recorded.';

    /** @var string The time the clock is held at, by a test that holds it. */
    private const string NOW = '2026-11-10 12:00:00';

    /**
     * Rate a hardware-protected passkey AAL3, so every level can be reached.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(CombinationPolicy::class, new LeveledCombinationPolicy);
    }

    /**
     * The package binds the recorder MFA's helper asks the container for.
     *
     * @return void
     */
    public function testTheRecorderIsBound(): void
    {
        self::assertInstanceOf(VerifiedSignInRecorderAdapter::class, $this->app?->make(VerifiedSignInRecorder::class));
    }

    /**
     * Each level, its factor type, and the route above it that stays shut.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\AssuranceLevel, 1: string, 2: ?string}>
     */
    public static function provideLevels(): iterable
    {
        yield 'AAL1, an email code' => [AssuranceLevel::AAL1, 'email', '/verified/aal2'];
        yield 'AAL2, an authenticator app' => [AssuranceLevel::AAL2, 'totp', '/verified/aal3'];
        yield 'AAL3, a hardware-protected passkey' => [AssuranceLevel::AAL3, 'passkey', null];
    }

    /**
     * MFA's helper verifies the session at exactly the level.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  string  $type
     * @param  ?string  $above
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideLevels')]
    public function testMfasHelperVerifiesThePersonAtExactlyTheLevel(AssuranceLevel $level, string $type, ?string $above): void
    {
        $person = $this->createPerson();

        self::assertSame($this, $this->actingAsVerified($person, $level));

        $this->assertReachesExactly($level, $above);

        $factor = $this->onlyFactorOf($person);

        self::assertSame($type, $factor->getType());
        self::assertSame(FactorStatus::CONFIRMED, $factor->getStatus());
        self::assertSame(self::GUARD, $factor->getApplication());
    }

    /**
     * A person who must verify at sign-in is verified through the pending one.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  string  $type
     * @param  ?string  $above
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideLevels')]
    public function testAPersonWhoMustVerifyAtSignInIsVerifiedThroughThePendingSignIn(AssuranceLevel $level, string $type, ?string $above): void
    {
        $person = $this->createPerson();
        $held   = $this->holdFactor($person, 'totp');

        $this->actingAsVerified($person, $level);

        $this->assertReachesExactly($level, $above);

        $session = $this->boundSession();
        $proofs  = $this->proofsOf($session);
        $factor  = $person->authFactors()->where('type', $type)->sole();

        self::assertInstanceOf(Factor::class, $factor);
        self::assertSame(SessionStatus::ACTIVE, $session->getStatus());
        self::assertCount(2, $proofs);
        self::assertSame(AuthenticationPurpose::SIGN_IN, $proofs[0]->purpose);
        self::assertSame($type, $proofs[0]->method);
        self::assertSame($factor->id, $proofs[0]->factor);
        self::assertSame($type === 'totp', $held->id === $factor->id);
    }

    /**
     * The session holds the password and a further proof made at that time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSessionHoldsThePasswordAndAFurtherProofMadeAtTheTimeAsked(): void
    {
        $this->travelTo(CarbonImmutable::parse(self::NOW));

        $person = $this->createPerson();
        $at     = CarbonImmutable::now()->subDay();

        $this->actingAsVerified($person, AssuranceLevel::AAL2, $at);

        $session = $this->boundSession();
        $proofs  = $this->proofsOf($session);

        self::assertTrue(CarbonImmutable::parse(self::NOW)->equalTo(CarbonImmutable::now()));
        self::assertSame($at->getTimestamp(), $session->getSignedInAt()?->getTimestamp());
        self::assertCount(2, $proofs);
        self::assertSame(AuthenticationProofKind::FIRST_FACTOR, $proofs[1]->kind);
        self::assertSame('password', $proofs[1]->method);
        self::assertSame(AuthenticationChannelKind::PASSWORD, $proofs[1]->channel->kind);
        self::assertSame(['pwd'], $proofs[1]->methods);
        self::assertTrue($at->equalTo($proofs[1]->authenticatedAt));
        self::assertSame(AuthenticationProofKind::ADDITIONAL_FACTOR, $proofs[0]->kind);
        self::assertSame($this->onlyFactorOf($person)->id, $proofs[0]->factor);
        self::assertTrue($at->equalTo($proofs[0]->authenticatedAt));

        $this->getJson('/verified/aal2')->assertOk();
    }

    /**
     * A pending sign-in is completed at the time asked, however far back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInIsCompletedAtTheTimeAsked(): void
    {
        $this->travelTo(CarbonImmutable::parse(self::NOW));

        $person = $this->createPerson();
        $held   = $this->holdFactor($person, 'totp');
        $at     = CarbonImmutable::now()->subHour();

        $this->actingAsVerified($person, AssuranceLevel::AAL2, $at);

        $session = $this->boundSession();
        $proofs  = $this->proofsOf($session);

        self::assertTrue(CarbonImmutable::parse(self::NOW)->equalTo(CarbonImmutable::now()));
        self::assertSame($at->getTimestamp(), $session->getSignedInAt()?->getTimestamp());
        self::assertCount(2, $proofs);
        self::assertTrue($at->equalTo($proofs[1]->authenticatedAt));
        self::assertSame($held->id, $proofs[0]->factor);
        self::assertTrue($at->equalTo($proofs[0]->authenticatedAt));
    }

    /**
     * The person's stored credentials are untouched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePersonsStoredCredentialsAreUntouched(): void
    {
        $person = $this->createPerson();
        $row    = $person->newQuery()->whereKey($person->getKey())->toBase()->first();

        $this->actingAsVerified($person, AssuranceLevel::AAL2);

        self::assertEquals($row, $person->newQuery()->whereKey($person->getKey())->toBase()->first());
        self::assertSame([PendingRequirement::MFA], $this->attemptSignIn($person)->pending?->requires);
    }

    /**
     * A verified person can be verified again with the factor already enrolled.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerifiedPersonCanBeVerifiedAgain(): void
    {
        $person = $this->createPerson();

        $this->actingAsVerified($person, AssuranceLevel::AAL2);

        $first = $this->boundSession();

        $this->actingAsVerified($person, AssuranceLevel::AAL2);

        self::assertFalse($first->is($this->boundSession()));
        self::assertCount(1, $person->authFactors()->get());

        $this->getJson('/verified/aal2')->assertOk();
    }

    /**
     * A refused sign-in throws, leaves no session and restores the clock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedSignInIsReportedAndLeavesNothing(): void
    {
        $this->travelTo(CarbonImmutable::parse(self::NOW));

        $person = $this->createPerson();

        try {
            $this->recorder()->begin($person, self::CODE_GUARD, CarbonImmutable::now()->subMinute());

            self::fail('The sign-in was not refused.');
        } catch (\LogicException $exception) {
            self::assertSame('The identity was not signed in on guard [codes] for actingAsVerified(): [method_not_allowed].', $exception->getMessage());
        }

        self::assertSame(0, $person->sessions()->count());
        self::assertTrue(CarbonImmutable::parse(self::NOW)->equalTo(CarbonImmutable::now()));
    }

    /**
     * An identity laravel-authentication cannot sign in is refused up front.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatIsNoIdentityOfLaravelAuthenticationsIsRefused(): void
    {
        $this->expectException(UnresolvedReferenceException::class);

        $this->recorder()->begin(self::createStub(MultiFactorAuthenticatable::class), self::GUARD, CarbonImmutable::now());
    }

    /**
     * A further proof leaving the sign-in pending is refused and rolled back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFurtherProofThatLeavesTheSignInPendingIsRefusedAndRolledBack(): void
    {
        $person = $this->createPerson();
        $held   = $this->holdFactor($person, 'totp');

        $this->app?->instance(CombinationPolicy::class, self::firstFactorOnly());

        $recorder = $this->recorder();
        $signIn   = $recorder->begin($person, self::GUARD, CarbonImmutable::now());
        $factor   = $recorder->factorReference($person, self::GUARD, AssuranceLevel::AAL2);

        self::assertSame($held->id, $factor);

        try {
            $recorder->record($person, self::totp($this->bindingOf($person, $signIn), $factor));

            self::fail('The further proof was not refused.');
        } catch (\LogicException $exception) {
            self::assertSame('The further proof did not activate the pending sign-in on guard [api] for actingAsVerified(): [pending: mfa].', $exception->getMessage());
        }

        self::assertSame(SessionStatus::PENDING->value, $person->sessions()->sole()->getAttribute('status'));

        $this->app?->instance(CombinationPolicy::class, new LeveledCombinationPolicy);

        $recorder->record($person, self::totp($this->bindingOf($person, $signIn), $factor));

        self::assertSame(SessionStatus::ACTIVE, $this->boundSession()->getStatus());
        self::assertCount(2, $this->proofsOf($this->boundSession()));
    }

    /**
     * A further proof for a pending sign-in that is gone is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInThatIsGoneIsRefused(): void
    {
        $person = $this->createPerson();
        $held   = $this->holdFactor($person, 'totp');

        $recorder = $this->recorder();
        $signIn   = $recorder->begin($person, self::GUARD, CarbonImmutable::now());

        $person->sessions()->delete();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The pending sign-in on guard [api] could not be read back.');

        $recorder->record($person, self::totp($this->bindingOf($person, $signIn), $held->id));
    }

    /**
     * The active sign-in's own first factor is kept; another is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheActiveSignInsOwnFirstFactorIsKeptAndAnotherRefused(): void
    {
        $person   = $this->createPerson();
        $recorder = $this->recorder();
        $binding  = $this->bindingOf($person, $recorder->begin($person, self::GUARD, CarbonImmutable::now()));

        $recorder->record($person, self::firstFactor('password', new Channel(ChannelKind::PASSWORD), $binding));

        self::assertCount(1, $this->proofsOf($this->boundSession()));

        $this->expectException(ProofRefusedException::class);

        $recorder->record($person, self::firstFactor('email', new Channel(ChannelKind::EMAIL, 'verified@example.test'), $binding));
    }

    /**
     * A pending sign-in's password is kept; another first factor is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePendingSignInsOwnPasswordIsKeptAndAnotherFirstFactorRefused(): void
    {
        $person   = $this->createPerson();
        $recorder = $this->recorder();

        $this->holdFactor($person, 'totp');

        $binding = $this->bindingOf($person, $recorder->begin($person, self::GUARD, CarbonImmutable::now()));
        $refused = 0;

        $recorder->record($person, self::firstFactor('password', new Channel(ChannelKind::PASSWORD), $binding));

        foreach ([['email', new Channel(ChannelKind::PASSWORD)], ['password', new Channel(ChannelKind::EMAIL, 'verified@example.test')]] as [$method, $channel]) {
            try {
                $recorder->record($person, self::firstFactor($method, $channel, $binding));
            } catch (ProofRefusedException $exception) {
                self::assertSame('Only the sign-in\'s own first factor, the password it was started with, is kept.', $exception->getMessage());

                $refused++;
            }
        }

        self::assertSame(2, $refused);
    }

    /**
     * A proof bound to another sign-in or identity is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofBoundToAnotherSignInOrIdentityIsRefused(): void
    {
        $person   = $this->createPerson();
        $other    = $this->createPerson('other@example.test');
        $recorder = $this->recorder();
        $signIn   = $recorder->begin($person, self::GUARD, CarbonImmutable::now());

        self::assertSame(2, $this->refusedUnbound($recorder, $person, [$this->bindingOf($person, 'another-sign-in'), $this->bindingOf($other, $signIn)]));
        self::assertCount(1, $this->proofsOf($this->boundSession()));
    }

    /**
     * Only the last pending sign-in is completed, and only for its identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyThePendingSignInBegunLastIsCompletedForItsOwnIdentity(): void
    {
        $person   = $this->createPerson();
        $other    = $this->createPerson('other@example.test');
        $recorder = $this->recorder();

        $this->holdFactor($person, 'totp');

        $earlier = $recorder->begin($person, self::GUARD, CarbonImmutable::now());
        $later   = $recorder->begin($person, self::GUARD, CarbonImmutable::now());

        self::assertSame(2, $this->refusedUnbound($recorder, $other, [$this->bindingOf($person, $later), $this->bindingOf($person, $earlier)]));
        self::assertSame(1, $this->refusedUnbound($recorder, $person, [$this->bindingOf($person, $earlier)]));
        self::assertSame(2, $person->sessions()->where('status', SessionStatus::PENDING->value)->count());
    }

    /**
     * Define a gated route per level and one reading the context's level.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        foreach (['aal1', 'aal2', 'aal3'] as $level) {
            $router->get('/verified/' . $level, static fn (): JsonResponse => new JsonResponse(['reached' => true]))
                ->middleware(['auth:' . self::GUARD, 'mfa:level=' . $level]);
        }

        $router->get(self::CONTEXT_ROUTE, static fn (): JsonResponse => new JsonResponse(['level' => Auth::context()?->get('mfa.level')]))
            ->middleware(['auth:' . self::GUARD]);
    }

    /**
     * Add a code-only guard beside the password one.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $app->make('config')->set('auth.guards.' . self::CODE_GUARD, [
            'driver'      => 'jwt',
            'provider'    => 'people',
            'application' => ['methods' => ['code']],
        ]);
    }

    /**
     * Assert the session passes the gate at the level and no higher.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  ?string  $above
     * @return void
     */
    private function assertReachesExactly(AssuranceLevel $level, ?string $above): void
    {
        $this->getJson('/verified/' . $level->value)->assertOk()->assertExactJson(['reached' => true]);
        $this->getJson(self::CONTEXT_ROUTE)->assertOk()->assertExactJson(['level' => $level->value]);

        if ($above === null) {
            return;
        }

        $this->getJson($above)->assertUnauthorized();
    }

    /**
     * How many of the bound proofs the recorder refused as unbound.
     *
     * @param  \SineMacula\Laravel\Iam\Testing\VerifiedSignInRecorderAdapter  $recorder
     * @param  \Tests\Fixtures\Models\Person  $identity
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\ProofBinding>  $bindings
     * @return int
     *
     * @throws \Throwable
     */
    private function refusedUnbound(VerifiedSignInRecorderAdapter $recorder, Person $identity, array $bindings): int
    {
        $refused = 0;

        foreach ($bindings as $binding) {
            try {
                $recorder->record($identity, self::totp($binding));
            } catch (ProofRefusedException $exception) {
                self::assertSame(self::UNBOUND, $exception->getMessage());

                $refused++;
            }
        }

        return $refused;
    }

    /**
     * A combination policy no further proof ever satisfies.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\CombinationPolicy
     */
    private static function firstFactorOnly(): CombinationPolicy
    {
        return new class implements CombinationPolicy {
            /**
             * Whether the factor may follow, as MFA's default judges.
             *
             * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
             * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $factor
             * @return bool
             */
            #[\Override]
            public function accepts(Proof $firstFactor, Channel $factor): bool
            {
                return (new DefaultCombinationPolicy)->accepts($firstFactor, $factor);
            }

            /**
             * The first proof alone, as MFA's default policy evaluates it.
             *
             * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
             * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
             * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
             */
            #[\Override]
            public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
            {
                return (new DefaultCombinationPolicy)->evaluate($requirement, ...array_slice($proofs, 0, 1));
            }
        };
    }

    /**
     * The recorder the package binds.
     *
     * @return \SineMacula\Laravel\Iam\Testing\VerifiedSignInRecorderAdapter
     */
    private function recorder(): VerifiedSignInRecorderAdapter
    {
        $recorder = $this->app?->make(VerifiedSignInRecorder::class);

        self::assertInstanceOf(VerifiedSignInRecorderAdapter::class, $recorder);

        return $recorder;
    }

    /**
     * What a proof of the person's sign-in is bound to.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $signIn
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private function bindingOf(Person $person, string $signIn): ProofBinding
    {
        $key = $person->getKey();

        return new ProofBinding($person->getMorphClass(), is_scalar($key) ? (string) $key : '', self::GUARD, $signIn, Purpose::SIGN_IN);
    }

    /**
     * The session the guard is bound to.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function boundSession(): EloquentSession&Model
    {
        $session = $this->app?->make(CurrentSession::class)->guard(self::GUARD)->session();

        self::assertInstanceOf(EloquentSession::class, $session);
        self::assertInstanceOf(Model::class, $session);

        return $session;
    }

    /**
     * A first factor made now, bound as given.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function firstFactor(string $method, Channel $channel, ProofBinding $binding): Proof
    {
        return new Proof(ProofKind::FIRST_FACTOR, $method, $channel, null, ObservedProperties::none(), CarbonImmutable::now(), $binding, 0);
    }

    /**
     * An AAL2 further proof made now with the factor, bound as given.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  ?string  $factor
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function totp(ProofBinding $binding, ?string $factor = null): Proof
    {
        return LevelEvidence::furtherProof(AssuranceLevel::AAL2, CarbonImmutable::now(), $binding, 0, $factor);
    }

    /**
     * Give the person a confirmed factor of the type.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $type
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     *
     * @throws \Throwable
     */
    private function holdFactor(Person $person, string $type): Factor
    {
        $factor = new Factor;
        $owner  = $factor->authenticatable();

        $factor->forceFill([
            $owner->getMorphType()        => $person->getMorphClass(),
            $owner->getForeignKeyName()   => $person->getKey(),
            $factor->getTypeName()        => $type,
            $factor->getApplicationName() => self::GUARD,
        ]);

        $factor->confirm();
        $factor->persist();

        return $factor;
    }

    /**
     * The one factor the person holds.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function onlyFactorOf(Person $person): Factor
    {
        $factors = $person->authFactors()->get()->all();

        self::assertCount(1, $factors);
        self::assertInstanceOf(Factor::class, $factors[0]);

        return $factors[0];
    }
}
