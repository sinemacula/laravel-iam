<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Testing\Concerns\InteractsWithIam;
use SineMacula\Laravel\Iam\Testing\VerifiedSession;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Testing\Concerns\InteractsWithMfa;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Testing\LeveledCombinationPolicy;
use Tests\TestCase;

/**
 * Acting on a session verified at a given level, with every adapter bound as an
 * application gets them: MFA's proof store is this package's, so MFA's own
 * `actingAsVerified()` is refused, and `actingOnVerifiedSession()` arranges the
 * same through `laravel-authentication`'s step-up instead, with a factor the
 * person holds, so the proof counts and MFA's route gate lets the session
 * through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerifiedSession::class)]
#[CoversClass(ProofStoreAdapter::class)]
#[CoversTrait(InteractsWithIam::class)]
final class InteractsWithIamTest extends TestCase
{
    use InteractsWithIam, InteractsWithMfa, MigratesMembers, SignsInPeople;

    /** @var string The route MFA's gate lets a session through at AAL2. */
    private const string AAL2_ROUTE = '/verified/aal2';

    /** @var string The route MFA's gate lets a session through at AAL3. */
    private const string AAL3_ROUTE = '/verified/aal3';

    /** @var string What MFA's own helper is refused with, naming the helper that arranges a verified session instead. */
    private const string REFUSAL = 'Only laravel-authentication records a session\'s proofs; a further proof reaches it through a step-up or a pending completion,'
        . ' or, in a test, through InteractsWithIam::actingOnVerifiedSession().';

    /**
     * MFA's `actingAsVerified()` records synthetic proofs through the proof
     * store, which only `laravel-authentication` writes to here, so it is
     * refused, and the refusal names the helper that arranges it instead.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfasActingAsVerifiedIsRefusedByThisPackagesStore(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $this->expectException(ProofRefusedException::class);
        $this->expectExceptionMessage(self::REFUSAL);

        $this->actingAsVerified($person, AssuranceLevel::AAL2);
    }

    /**
     * A session verified at AAL2 passes MFA's route gate on the next request,
     * where it did not before.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerifiedSessionPassesMfasRouteGate(): void
    {
        $session = $this->signIn($this->createPerson())->record;

        $this->actingOnSession($session)->getJson(self::AAL2_ROUTE)->assertUnauthorized();

        $this->actingOnVerifiedSession($session)->getJson(self::AAL2_ROUTE)->assertOk()->assertExactJson(['reached' => true]);
    }

    /**
     * The helper is public, so code outside the test case, a helper object of
     * the application's own say, can arrange a verified session through it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCodeOutsideTheTestCaseCanActOnAVerifiedSession(): void
    {
        $session = $this->signIn($this->createPerson())->record;
        $outside = \Closure::bind(static fn (InteractsWithIamTest $test): InteractsWithIamTest => $test->actingOnVerifiedSession($session), null, null);

        self::assertSame($this, $outside($this));

        $this->getJson(self::AAL2_ROUTE)->assertOk();
    }

    /**
     * The levels and the further proof each is verified with.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\AssuranceLevel, 1: string, 2: \SineMacula\Laravel\Mfa\Enums\ChannelKind, 3: bool, 4: list<string>}>
     */
    public static function levels(): iterable
    {
        yield 'AAL1, an email code' => [AssuranceLevel::AAL1, 'email', ChannelKind::EMAIL, false, ['otp']];
        yield 'AAL2, an authenticator app' => [AssuranceLevel::AAL2, 'totp', ChannelKind::AUTHENTICATOR_APP, true, ['otp']];
        yield 'AAL3, a hardware-protected passkey' => [AssuranceLevel::AAL3, 'passkey', ChannelKind::PASSKEY, true, ['pop', 'user', 'hwk']];
    }

    /**
     * The further proof is recorded by `laravel-authentication` on the session,
     * for a step-up, made with a confirmed factor the person holds on the
     * guard's application, so the store counts it after the first factor, and
     * the session evaluates at exactly the level.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  string  $type
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $channel
     * @param  bool  $multifactor
     * @param  list<string>  $methods
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('levels')]
    public function testTheFurtherProofIsRecordedWithAFactorThePersonHolds(AssuranceLevel $level, string $type, ChannelKind $channel, bool $multifactor, array $methods): void
    {
        $this->app?->instance(CombinationPolicy::class, new LeveledCombinationPolicy);

        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;

        $this->actingOnVerifiedSession($session, $level);

        $factor   = $this->onlyFactorOf($person);
        $recorded = $this->furtherProofOf($session);
        $proofs   = $this->app?->make(ProofStore::class)->proofs($person, self::GUARD) ?? [];

        self::assertSame($type, $factor->getType());
        self::assertSame(FactorStatus::CONFIRMED, $factor->getStatus());
        self::assertSame(self::GUARD, $factor->getApplication());

        self::assertSame(AuthenticationPurpose::STEP_UP, $recorded->purpose);
        self::assertSame($type, $recorded->method);
        self::assertSame($factor->id, $recorded->factor);
        self::assertSame($channel->value, $recorded->channel->kind->value);
        self::assertSame($channel === ChannelKind::EMAIL ? VerifiedSession::EMAIL_ADDRESS : $factor->id, $recorded->channel->reference);
        self::assertTrue($recorded->evaluation?->accepted);
        self::assertSame($multifactor, $recorded->evaluation->multifactor);
        self::assertSame($methods, $recorded->methods);

        self::assertSame([ProofKind::FIRST_FACTOR, ProofKind::ADDITIONAL_FACTOR], array_map(static fn (Proof $proof): ProofKind => $proof->kind, $proofs));
        self::assertSame($factor->id, $proofs[1]->reference);
    }

    /**
     * A passkey's proof observes presence, user verification, phishing
     * resistance and a hardware-protected key, so a policy that rates such
     * evidence AAL3 lets the session through an AAL3 gate.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAal3SessionPassesAnAal3GateUnderAPolicyThatRatesItSo(): void
    {
        $this->app?->instance(CombinationPolicy::class, new LeveledCombinationPolicy);

        $session = $this->signIn($this->createPerson())->record;

        $this->actingOnVerifiedSession($session, AssuranceLevel::AAL3)->getJson(self::AAL3_ROUTE)->assertOk();

        $observed = $this->furtherProofOf($session)->observed;

        self::assertTrue($observed->userPresence);
        self::assertTrue($observed->userVerification);
        self::assertTrue($observed->phishingResistant);
        self::assertSame(KeyProtection::HARDWARE->value, $observed->keyProtection?->value);
    }

    /**
     * MFA's default policy rates a passkey AAL2, so asking for AAL3 under it
     * fails, naming what was asked, what was reached and what is unmet.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAal3IsRefusedUnderAPolicyThatDoesNotRateItSo(): void
    {
        $session = $this->signIn($this->createPerson())->record;

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Requested aal3 with additional verification; reached aal2; unmet: minimum_level.');

        $this->actingOnVerifiedSession($session, AssuranceLevel::AAL3);
    }

    /**
     * A session already verified past the level asked for is refused rather
     * than handed to a test that meant it to stop short.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionAlreadyPastTheLevelIsRefused(): void
    {
        $session = $this->signIn($this->createPerson())->record;

        $this->actingOnVerifiedSession($session);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Requested aal1 with additional verification; reached aal2; unmet: none.');

        $this->actingOnVerifiedSession($session, AssuranceLevel::AAL1);
    }

    /**
     * The unclassified level supports nothing, so it is refused before any
     * factor is enrolled or any proof recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheUnclassifiedLevelIsRefusedBeforeAnythingChanges(): void
    {
        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;

        try {
            $this->actingOnVerifiedSession($session, AssuranceLevel::UNCLASSIFIED);

            self::fail('A session was verified at the unclassified level.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A session cannot be verified at the unclassified level: it supports no level.', $exception->getMessage());
        }

        self::assertSame(0, $person->authFactors()->count());
        self::assertCount(1, $this->proofsOf($session));
    }

    /**
     * Define the routes MFA's gate guards, on the stateless guard.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->get(self::AAL2_ROUTE, static fn (): JsonResponse => new JsonResponse(['reached' => true]))
            ->middleware(['auth:' . self::GUARD, 'mfa:level=aal2']);

        $router->get(self::AAL3_ROUTE, static fn (): JsonResponse => new JsonResponse(['reached' => true]))
            ->middleware(['auth:' . self::GUARD, 'mfa:level=aal3']);
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

    /**
     * The newest proof `laravel-authentication` recorded on the session,
     * failing the test unless it is the only one after the first factor.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \Throwable
     */
    private function furtherProofOf(EloquentSession&Model $session): RecordedProof
    {
        $proofs = $this->proofsOf($session);

        self::assertCount(2, $proofs);
        self::assertNotSame(AuthenticationChannelKind::PASSWORD, $proofs[0]->channel->kind);

        return $proofs[0];
    }
}
