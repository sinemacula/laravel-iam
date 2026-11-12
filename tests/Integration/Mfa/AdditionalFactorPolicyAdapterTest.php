<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\AdditionalFactorPolicyAdapter;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel as MfaLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind as MfaProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;
use SineMacula\Laravel\Mfa\Testing\Seams\RequirementSeamContract;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authentication`'s additional-factor policy
 * answered by MFA's requirement policy alone (IAM-3.1): a sign-in MFA asks
 * nothing further of activates, one it asks a further factor of waits for it,
 * MFA is asked about the identity on the application with the first factor as
 * its own proof, and its answer crosses part for part and age for age
 * (IAM-3.14), the same however often and in whatever order it is asked.
 *
 * The adapter refuses only by throwing: an identity MFA holds no factors for,
 * or whose key names nothing, is refused (IAM-8.2), as is an answer
 * `laravel-authentication` cannot hold, which rolls back the proof
 * `laravel-authentication` was settling the session with, on every engine and
 * also at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL. The
 * policy only reads, so it takes no lock of its own to order.
 *
 * The sessions are real ones, signed in through `laravel-authentication` with a
 * password. The capability's switch is off, so every other seam keeps its
 * member's default, `laravel-authentication`'s requirement check included,
 * which meets nothing: what the policy asks is what the session waits for. MFA
 * has no kit for its requirement policy; its requirement seams' statelessness
 * assertion is applied to the answers instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdditionalFactorPolicyAdapter::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class AdditionalFactorPolicyAdapterTest extends TestCase
{
    use MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The authenticator app factor the further proof is made with. */
    private const string FACTOR = 'factor-authenticator-app';

    /** @var int A maximum age `laravel-authentication` cannot hold: over a year. */
    private const int BEYOND_A_YEAR = 31536001;

    /**
     * Bind the adapter, as an application would.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->bind(AdditionalFactorPolicy::class, AdditionalFactorPolicyAdapter::class);
    }

    /**
     * Rows of `[MFA's requirement mode for the application, whether the sign-in
     * waits for a further factor]`.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideRequirementModes(): iterable
    {
        yield 'never' => ['never', false];

        yield 'once enrolled, by someone not enrolled' => ['enrolled', false];

        yield 'always' => ['always', true];
    }

    /**
     * A sign-in MFA asks nothing further of activates, and one it asks a
     * further factor of waits for an additional verification.
     *
     * @param  string  $mode
     * @param  bool  $waits
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRequirementModes')]
    public function testASignInWaitsForWhatMfaAsks(string $mode, bool $waits): void
    {
        Config::set('mfa.applications.' . self::GUARD . '.requirement', $mode);

        $result = $this->attemptSignIn($this->createPerson());

        self::assertSame($waits, $result->isPending());
        self::assertSame(!$waits, $result->isSignedIn());
        self::assertEquals($waits ? new Requirement(new RequirementPart(null)) : null, $result->pending?->requirement);
    }

    /**
     * MFA's policy is asked about the person, on the application, with the
     * password the person signed in with as MFA's first factor, bound to the
     * sign-in no session key can name and stamped with the person's current
     * verification generation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfaIsAskedAboutTheIdentityWithItsFirstFactor(): void
    {
        $person = $this->createPerson();
        $key    = $person->getKey();
        $asked  = [];

        self::assertIsInt($key);

        VerificationGeneration::advance($person);
        VerificationGeneration::advance($person);

        $this->answerRequirementsWith(static function (MultiFactorAuthenticatable $identity, string $application, Proof $firstFactor) use (&$asked): MfaRequirement {

            $asked[] = [$identity, $application, $firstFactor];

            return MfaRequirement::none();
        });

        self::assertTrue($this->attemptSignIn($person)->isSignedIn());
        self::assertCount(1, $asked);

        [$identity, $application, $firstFactor] = $asked[0];

        self::assertInstanceOf(Person::class, $identity);
        self::assertTrue($person->is($identity));
        self::assertSame(self::GUARD, $application);
        self::assertSame(
            [MfaProofKind::FIRST_FACTOR, 'password', MfaChannelKind::PASSWORD, 2],
            [$firstFactor->kind, $firstFactor->method, $firstFactor->channel?->kind, $firstFactor->generation],
        );
        self::assertSame([$person->getMorphClass(), (string) $key, self::GUARD, SignIn::UNNAMED, MfaPurpose::SIGN_IN], [
            $firstFactor->binding->identityType,
            $firstFactor->binding->identityKey,
            $firstFactor->binding->application,
            $firstFactor->binding->sessionId,
            $firstFactor->binding->purpose,
        ]);
    }

    /**
     * MFA's answer is `laravel-authentication`'s requirement, part for part and
     * age for age.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfasAnswerCrossesPartForPartAndAgeForAge(): void
    {
        $this->answerRequirementsWith(static fn (): MfaRequirement => MfaRequirement::none()
            ->withMultifactor(300)
            ->withMinimumLevel(MfaLevel::AAL2, 600)
            ->withPhishingResistance());

        $result = $this->attemptSignIn($this->createPerson());

        $expected = new Requirement(null, new RequirementPart(300), new LevelRequirement(AssuranceLevel::AAL2, 600), new RequirementPart(null));

        self::assertEquals($expected, $result->pending?->requirement);
    }

    /**
     * The policy keeps no state between calls: the same question answers the
     * same requirement whatever was asked in between.
     *
     * @return void
     */
    public function testThePolicyKeepsNoStateBetweenCalls(): void
    {
        $asksMore = $this->createPerson();
        $asksNone = $this->createPerson();

        $this->answerRequirementsWith(static fn (MultiFactorAuthenticatable $identity): MfaRequirement => $identity === $asksMore
            ? MfaRequirement::none()->withAdditionalVerification(120)
            : MfaRequirement::none());

        $translator = new RequirementTranslator;

        RequirementSeamContract::assertKeepsNoStateBetweenCalls(
            fn (): MfaRequirement => $translator->toMfa($this->adapter()->requirementFor(self::context($asksMore))),
            fn (): MfaRequirement => $translator->toMfa($this->adapter()->requirementFor(self::context($asksNone))),
        );
    }

    /**
     * An identity MFA holds no factors for is refused, naming its type and
     * MFA's contract it does not implement.
     *
     * @return void
     */
    public function testAnIdentityMfaHoldsNoFactorsForIsRefused(): void
    {
        $identity = new class (['id' => 7]) extends GenericUser implements Identity {};

        self::assertUnresolvedIdentity(fn (): mixed => $this->adapter()->requirementFor(self::context($identity)), $identity::class, 'MultiFactorAuthenticatable');
    }

    /**
     * An identity whose key names nothing is refused.
     *
     * @return void
     */
    public function testAnIdentityWhoseKeyNamesNothingIsRefused(): void
    {
        $this->expectException(UnsupportedIdentifierException::class);

        $this->adapter()->requirementFor(self::context(new Person));
    }

    /**
     * An answer `laravel-authentication` cannot hold refuses the sign-in by
     * throwing, before any session is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAnswerTheSessionCannotHoldRefusesTheSignIn(): void
    {
        $this->answerRequirementsWith(static fn (): MfaRequirement => MfaRequirement::none()->withAdditionalVerification(self::BEYOND_A_YEAR));

        $person = $this->createPerson();

        try {
            $this->attemptSignIn($person);

            self::fail('An answer laravel-authentication cannot hold was handed to it.');
        } catch (\InvalidArgumentException) {
            // The sessions are asserted below.
        }

        self::assertSame(0, $person->sessions()->count());
    }

    /**
     * An answer `laravel-authentication` cannot hold, refused while it settles
     * a pending session with a further factor, rolls back with the whole
     * transaction: the proof is not kept and the session still waits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalInsideTheMembersTransactionRollsBackTheProof(): void
    {
        $this->assertARefusalRollsBackTheProof();
    }

    /**
     * The refusal rolls back the same way on MySQL and PostgreSQL at READ
     * COMMITTED and REPEATABLE READ.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARefusalRollsBackTheProofAtEachIsolationLevel(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $this->assertARefusalRollsBackTheProof();
    }

    /**
     * Assert an answer `laravel-authentication` cannot hold, refused while it
     * settles a pending session with a further factor, rolls back with the
     * whole transaction: the proof is not kept and the session still waits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function assertARefusalRollsBackTheProof(): void
    {
        $this->answerRequirementsWith(static fn (): MfaRequirement => MfaRequirement::none()->withAdditionalVerification());

        $person  = $this->createPerson();
        $pending = $this->attemptSignIn($person);
        $proofs  = DB::table('authentication_proofs')->count();

        self::assertNotNull($pending->credential);
        self::assertNotNull($pending->pending);

        $proof = new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP, self::FACTOR),
            self::FACTOR,
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($person, self::GUARD, $pending->pending->id, Purpose::SIGN_IN),
        );

        $this->answerRequirementsWith(static fn (): MfaRequirement => MfaRequirement::none()->withAdditionalVerification(self::BEYOND_A_YEAR));

        try {
            $this->sessions()->satisfy($pending->credential, $proof, self::client());

            self::fail('An answer laravel-authentication cannot hold was handed to it.');
        } catch (\InvalidArgumentException) {
            // The proof and the session are asserted below.
        }

        $this->answerRequirementsWith(static fn (): MfaRequirement => MfaRequirement::none()->withAdditionalVerification());

        self::assertSame($proofs, DB::table('authentication_proofs')->count());
        self::assertNotNull($this->sessions()->pending($pending->credential));
    }

    /**
     * Have MFA's requirement policy answer as the closure does.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable, string, \SineMacula\Laravel\Mfa\Proofs\Proof): \SineMacula\Laravel\Mfa\Requirements\Requirement  $answer
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function answerRequirementsWith(\Closure $answer): void
    {
        $this->app?->instance(RequirementPolicy::class, new readonly class ($answer) implements RequirementPolicy {
            /**
             * Constructor.
             *
             * @formatter:off
             *
             * @phpcs:disable Generic.Files.LineLength.TooLong
             *
             * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable, string, \SineMacula\Laravel\Mfa\Proofs\Proof): \SineMacula\Laravel\Mfa\Requirements\Requirement  $answer
             *
             * @phpcs:enable Generic.Files.LineLength.TooLong
             *
             * @formatter:on
             */
            public function __construct(

                /** Answers every question. */
                private \Closure $answer,
            ) {}

            /**
             * The requirement the closure answers.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
             * @param  string  $application
             * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
             * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(MultiFactorAuthenticatable $identity, string $application, Proof $firstFactor): MfaRequirement
            {
                return ($this->answer)($identity, $application, $firstFactor);
            }
        });
    }

    /**
     * The adapter, with the collaborators the container holds now.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\AdditionalFactorPolicyAdapter
     */
    private function adapter(): AdditionalFactorPolicyAdapter
    {
        $adapter = $this->app?->make(AdditionalFactorPolicyAdapter::class);

        self::assertInstanceOf(AdditionalFactorPolicyAdapter::class, $adapter);

        return $adapter;
    }

    /**
     * The context of the identity's sign-in on the application with its
     * password, as `laravel-authentication` builds it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext
     */
    private static function context(Identity $identity): AdditionalFactorContext
    {
        $channel     = new Channel(ChannelKind::PASSWORD);
        $proved      = CarbonImmutable::now();
        $firstFactor = new RecordedProof('proof-first', ProofKind::FIRST_FACTOR, Purpose::SIGN_IN, 'password', $channel, null, new ObservedProperties, null, ['pwd'], $proved);

        return new AdditionalFactorContext(self::GUARD, $identity, $firstFactor, new ClientContext('127.0.0.1', 'tests'), null, null, null);
    }

    /**
     * Assert that the callback is refused for an identity that cannot be
     * resolved, with a message naming the identity's type and what it lacks.
     *
     * @param  \Closure(): mixed  $callback
     * @param  string  $type
     * @param  string  $lacking
     * @return void
     */
    private static function assertUnresolvedIdentity(\Closure $callback, string $type, string $lacking): void
    {
        try {
            $callback();
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
            self::assertStringContainsString(sprintf('[%s]', $type), $exception->getMessage());
            self::assertStringContainsString($lacking, $exception->getMessage());

            return;
        }

        self::fail('The identity was resolved.');
    }
}
