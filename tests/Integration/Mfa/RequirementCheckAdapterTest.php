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
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck as AuthenticationRequirementCheck;
use SineMacula\Laravel\Authentication\Models\Session as SessionModel;
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
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\AdditionalFactorPolicyAdapter;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\RequirementCheckAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Assurance\Evaluation as MfaEvaluation;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind as MfaProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\ProofRequirementCheck;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authentication`'s requirement check answered
 * by MFA's (IAM-3.2): a sign-in its password alone does not meet waits for a
 * further factor, one that meets it activates, MFA judges the session's own
 * proofs bound to its sign-in, read in one bounded query, and the parts MFA
 * leaves unmet are the answer (IAM-3.14).
 *
 * The adapter refuses only by throwing: an identity MFA holds no factors for,
 * and a session or identity whose key names nothing, are refused (IAM-8.2), and
 * a refusal inside `laravel-authentication`'s transaction rolls back the proof
 * it was judging. Judged under the session row's lock, it takes no MFA lock, so
 * it never waits on MFA's identity state or factors, on MySQL or PostgreSQL, at
 * either isolation level.
 *
 * The sessions are real ones, signed in through `laravel-authentication` with a
 * password. The capability's switch is off, so MFA's other seams keep their
 * defaults, and the test binds this adapter and the additional-factor policy's
 * as an application would; MFA has no kit for its requirement check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementCheckAdapter::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class RequirementCheckAdapterTest extends TestCase
{
    use MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The authenticator app factor the further proofs are made with. */
    private const string FACTOR = 'factor-authenticator-app';

    /** @var string The passkey factor the phishing-resistant proofs are made with. */
    private const string PASSKEY = 'factor-passkey';

    /** @var int How long the judging side waits for a lock before giving up, in seconds. */
    private const int LOCK_WAIT_SECONDS = 2;

    /**
     * Bind this adapter and the additional-factor policy's, and have MFA ask a
     * further factor of every sign-in.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->bind(AdditionalFactorPolicy::class, AdditionalFactorPolicyAdapter::class);
        $this->app?->bind(AuthenticationRequirementCheck::class, RequirementCheckAdapter::class);

        Config::set('mfa.applications.' . self::GUARD . '.requirement', 'always');
    }

    /**
     * A sign-in whose password alone does not meet what MFA asks waits for the
     * further factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInThePasswordAloneDoesNotMeetWaitsForAFurtherFactor(): void
    {
        $result = $this->attemptSignIn($this->createPerson());

        self::assertTrue($result->isPending());
        self::assertNotNull($result->pending?->requirement->additionalVerification);
    }

    /**
     * A further factor that meets what MFA asks activates the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFurtherFactorThatMeetsTheRequirementActivatesTheSession(): void
    {
        $person  = $this->createPerson();
        $pending = $this->attemptSignIn($person);

        $result = $this->satisfy($person, $pending, self::authenticatorApp());

        self::assertTrue($result->isSignedIn());
    }

    /**
     * A further factor that meets too little of what MFA asks leaves the
     * session pending, and one that meets the rest activates it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFurtherFactorThatMeetsTooLittleLeavesTheSessionPending(): void
    {
        $this->answerRequirementsWith(static fn (): MfaRequirement => MfaRequirement::none()->withPhishingResistance());

        $person  = $this->createPerson();
        $pending = $this->attemptSignIn($person);

        $stillPending = $this->satisfy($person, $pending, self::authenticatorApp());

        self::assertTrue($stillPending->isPending());
        self::assertTrue($this->satisfy($person, $pending, self::passkey())->isSignedIn());
    }

    /**
     * MFA judges the session's first factor and its further proofs, each bound
     * to the person, the application and the sign-in judged, under the person's
     * current verification generation; at sign-in, before the session is
     * written, the sign-in no session key can name.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfaJudgesTheSessionsProofsBoundToItsSignIn(): void
    {
        $person = $this->createPerson();
        $key    = $person->getKey();
        $judged = [];

        self::assertIsInt($key);

        VerificationGeneration::advance($person);

        $this->checkProofsWith(static function (MfaRequirement $requirement, array $proofs) use (&$judged): MfaEvaluation {

            $judged[] = $proofs;

            return (new ProofRequirementCheck(app()))->check($requirement, ...$proofs);
        });

        $pending = $this->attemptSignIn($person);

        self::assertNotNull($pending->pending);
        self::assertTrue($this->satisfy($person, $pending, self::authenticatorApp())->isSignedIn());

        $atSignIn = $judged[0] ?? [];
        $settling = end($judged);

        self::assertIsArray($settling);
        self::assertSame([MfaProofKind::FIRST_FACTOR], self::kinds($atSignIn));
        self::assertSame(SignIn::UNNAMED, $atSignIn[0]->binding->sessionId);
        self::assertSame([MfaProofKind::FIRST_FACTOR, MfaProofKind::ADDITIONAL_FACTOR], self::kinds($settling));
        self::assertSame(MfaChannelKind::PASSWORD, $settling[0]->channel?->kind);
        self::assertSame([self::FACTOR, MfaPurpose::SIGN_IN], [$settling[1]->reference, $settling[1]->binding->purpose]);

        $expected = [$person->getMorphClass(), (string) $key, self::GUARD, $this->signInReference($pending->pending->session), 1];

        foreach ($settling as $proof) {
            self::assertSame($expected, [
                $proof->binding->identityType,
                $proof->binding->identityKey,
                $proof->binding->application,
                $proof->binding->sessionId,
                $proof->generation,
            ]);
        }
    }

    /**
     * Rows of `[requirement, the oldest time asked for, in seconds before the
     * time judged, or null for none]`: the longest maximum age of the parts,
     * none when a part has no maximum age, and the time judged itself when no
     * part is asked for.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Requirements\Requirement, 1: ?int}>
     */
    public static function provideReadBounds(): iterable
    {
        yield 'the longest maximum age' => [
            new Requirement(new RequirementPart(300), new RequirementPart(60), new LevelRequirement(AssuranceLevel::AAL1, 900), new RequirementPart(120)),
            900,
        ];

        yield 'one part' => [new Requirement(multifactor: new RequirementPart(45)), 45];

        yield 'a part without a maximum age' => [new Requirement(new RequirementPart(300), phishingResistance: new RequirementPart(null)), null];

        yield 'no part' => [new Requirement, 0];
    }

    /**
     * The proofs are read in one query bounded by the requirement: only those
     * made since the oldest time a part's maximum age allows, only the kinds a
     * requirement can be met with beside the first factor (never a
     * reauthentication at the external provider), and as many as one query
     * returns.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  ?int  $since
     * @return void
     */
    #[DataProvider('provideReadBounds')]
    public function testTheProofsAreReadInOneQueryBoundedByTheRequirement(Requirement $requirement, ?int $since): void
    {
        $now   = CarbonImmutable::parse('2026-11-05 10:00:00');
        $reads = [];

        $reader = static function (?CarbonImmutable $from, ?array $kinds, int $limit) use (&$reads): array {

            $reads[] = [$from?->toDateTimeString(), $kinds, $limit];

            return [];
        };

        $this->adapter()->evaluate(new RequirementSubject($this->createPerson(), self::GUARD, null, self::firstFactor($now), $now, $reader), $requirement);

        self::assertSame([[
            $since === null ? null : $now->subSeconds($since)->toDateTimeString(),
            [ProofKind::FIRST_FACTOR_REAUTHENTICATION, ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE],
            RequirementSubject::MAX_LIMIT,
        ]], $reads);
    }

    /**
     * The proofs read, newest first, reach MFA after the first factor oldest
     * first.
     *
     * @return void
     */
    public function testTheProofsReachMfaAfterTheFirstFactorOldestFirst(): void
    {
        $now    = CarbonImmutable::now()->startOfSecond();
        $judged = [];

        $this->checkProofsWith(static function (MfaRequirement $requirement, array $proofs) use (&$judged): MfaEvaluation {

            $judged = array_map(static fn (Proof $proof): string => $proof->method, $proofs);

            return (new ProofRequirementCheck(app()))->check($requirement, ...$proofs);
        });

        $further = [self::further('newer', $now->subSeconds(5)), self::further('older', $now->subSeconds(10))];

        $this->adapter()->evaluate(self::subject($this->createPerson(), $now, $further), new Requirement(new RequirementPart(null)));

        self::assertSame(['password', 'older', 'newer'], $judged);
    }

    /**
     * Rows of `[requirement, the parts left unmet]` for a session holding a
     * password and an authenticator app's code made half a minute ago: each
     * part MFA finds met is met, and each it does not is the answer.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Authentication\Requirements\Requirement, list<\SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind>}>
     */
    public static function provideJudgements(): iterable
    {
        yield 'an additional verification' => [new Requirement(new RequirementPart(null)), []];

        yield 'multifactor within its age' => [new Requirement(multifactor: new RequirementPart(600)), []];

        yield 'multifactor beyond its age' => [new Requirement(multifactor: new RequirementPart(5)), [RequirementKind::MULTIFACTOR]];

        yield 'the level the proofs reach' => [new Requirement(minimumLevel: new LevelRequirement(AssuranceLevel::AAL2, null)), []];

        yield 'a level beyond them' => [
            new Requirement(new RequirementPart(null), minimumLevel: new LevelRequirement(AssuranceLevel::AAL3, null)),
            [RequirementKind::MINIMUM_LEVEL],
        ];

        yield 'phishing resistance' => [
            new Requirement(new RequirementPart(null), phishingResistance: new RequirementPart(null)),
            [RequirementKind::PHISHING_RESISTANCE],
        ];
    }

    /**
     * The parts MFA leaves unmet are the answer.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  list<\SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind>  $unmet
     * @return void
     */
    #[DataProvider('provideJudgements')]
    public function testThePartsMfaLeavesUnmetAreTheAnswer(Requirement $requirement, array $unmet): void
    {
        $now     = CarbonImmutable::now()->startOfSecond();
        $subject = self::subject($this->createPerson(), $now, [self::further('totp', $now->subSeconds(30))], $now->subSeconds(40));

        self::assertSame($unmet, $this->adapter()->evaluate($subject, $requirement)->unmet);
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

        $subject = self::subject($identity, CarbonImmutable::now());

        $exception = self::assertUnresolved(ReferenceKind::IDENTITY, fn (): mixed => $this->adapter()->evaluate($subject, self::additionalVerification()));

        self::assertStringContainsString(sprintf('[%s]', $identity::class), $exception->getMessage());
        self::assertStringContainsString('MultiFactorAuthenticatable', $exception->getMessage());
    }

    /**
     * An identity whose key names nothing is refused.
     *
     * @return void
     */
    public function testAnIdentityWhoseKeyNamesNothingIsRefused(): void
    {
        $subject = self::subject(new Person, CarbonImmutable::now());

        $this->expectException(UnsupportedIdentifierException::class);

        $this->adapter()->evaluate($subject, self::additionalVerification());
    }

    /**
     * A session whose key names nothing is refused, naming the application.
     *
     * @return void
     */
    public function testASessionWhoseKeyNamesNothingIsRefused(): void
    {
        $now     = CarbonImmutable::now();
        $subject = new RequirementSubject($this->createPerson(), self::GUARD, new SessionModel, self::firstFactor($now), $now, static fn (): array => []);

        $exception = self::assertUnresolved(ReferenceKind::SESSION, fn (): mixed => $this->adapter()->evaluate($subject, self::additionalVerification()));

        self::assertSame(self::GUARD, $exception->application);
    }

    /**
     * A proof MFA would not build, refused while `laravel-authentication`
     * judges the session it was just recorded on, rolls back with the whole
     * transaction: the proof is not kept and the session still waits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalInsideTheMembersTransactionRollsBackTheProof(): void
    {
        $person  = $this->createPerson();
        $pending = $this->attemptSignIn($person);
        $proofs  = DB::table('authentication_proofs')->count();

        try {
            $this->satisfy($person, $pending, self::authenticatorApp(factor: null));

            self::fail('A proof MFA would not build was judged.');
        } catch (\InvalidArgumentException) {
            // The proof and the session are asserted below.
        }

        self::assertSame($proofs, DB::table('authentication_proofs')->count());
        self::assertTrue($this->satisfy($person, $pending, self::authenticatorApp())->isSignedIn());
    }

    /**
     * Judging the session under its row's lock takes no MFA lock: with the
     * person's identity state and factors held on another connection, the
     * further factor still activates the session, without waiting.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testJudgingTheSessionTakesNoMfaLock(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person = $this->createPerson();

        VerificationGeneration::advance($person);

        $pending = $this->attemptSignIn($person);
        $other   = self::otherConnection();

        $other->beginTransaction();

        try {
            self::holdMfaRows($other, $person);

            $result = $this->satisfy($person, $pending, self::authenticatorApp());
        } finally {
            $other->rollBack();
        }

        self::assertTrue($result->isSignedIn());
    }

    /**
     * Satisfy the pending sign-in with a further factor proved now, bound to
     * the person, the application and the pending session for sign-in.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $pending
     * @param  \Closure(\SineMacula\Laravel\Authentication\Proofs\ProofBinding): \SineMacula\Laravel\Authentication\Proofs\ProofResult  $factor
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function satisfy(Person $person, SignInResult $pending, \Closure $factor): SignInResult
    {
        self::assertNotNull($pending->credential);
        self::assertNotNull($pending->pending);

        $proof = $factor(new ProofBinding($person, self::GUARD, $pending->pending->id, Purpose::SIGN_IN));

        return $this->sessions()->satisfy($pending->credential, $proof, self::client());
    }

    /**
     * An authenticator app's code, made now, recorded with the factor given.
     *
     * @param  ?string  $factor
     * @return \Closure(\SineMacula\Laravel\Authentication\Proofs\ProofBinding): \SineMacula\Laravel\Authentication\Proofs\ProofResult
     */
    private static function authenticatorApp(?string $factor = self::FACTOR): \Closure
    {
        $channel = new Channel(ChannelKind::AUTHENTICATOR_APP, self::FACTOR);

        return static fn (ProofBinding $binding): ProofResult => self::furtherProof('totp', $channel, $factor, new ObservedProperties, ['otp'], $binding);
    }

    /**
     * A passkey's assertion, made now, verifying its user and resisting
     * phishing.
     *
     * @return \Closure(\SineMacula\Laravel\Authentication\Proofs\ProofBinding): \SineMacula\Laravel\Authentication\Proofs\ProofResult
     */
    private static function passkey(): \Closure
    {
        $channel  = new Channel(ChannelKind::PASSKEY, self::PASSKEY);
        $observed = new ObservedProperties(true, true, phishingResistant: true);

        return static fn (ProofBinding $binding): ProofResult => self::furtherProof('passkey', $channel, self::PASSKEY, $observed, ['pop', 'user'], $binding);
    }

    /**
     * A further factor proved now, accepted as multifactor.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @param  ?string  $factor
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @param  list<string>  $methods
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofResult
     */
    private static function furtherProof(string $method, Channel $channel, ?string $factor, ObservedProperties $observed, array $methods, ProofBinding $binding): ProofResult
    {
        return new ProofResult(ProofKind::ADDITIONAL_FACTOR, $method, $channel, $factor, $observed, new Evaluation(true, true), $methods, CarbonImmutable::now(), $binding);
    }

    /**
     * A requirement of an additional verification, of any age.
     *
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    private static function additionalVerification(): Requirement
    {
        return new Requirement(new RequirementPart(null));
    }

    /**
     * Have MFA's requirement policy answer as the closure does.
     *
     * @param  \Closure(): \SineMacula\Laravel\Mfa\Requirements\Requirement  $answer
     * @return void
     */
    private function answerRequirementsWith(\Closure $answer): void
    {
        $this->app?->instance(RequirementPolicy::class, new readonly class ($answer) implements RequirementPolicy {
            /**
             * Constructor.
             *
             * @param  \Closure(): \SineMacula\Laravel\Mfa\Requirements\Requirement  $answer
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
                return ($this->answer)();
            }
        });
    }

    /**
     * Have MFA's requirement check judge as the closure does, given the proofs
     * as a list.
     *
     * @param  \Closure(\SineMacula\Laravel\Mfa\Requirements\Requirement, list<\SineMacula\Laravel\Mfa\Proofs\Proof>): \SineMacula\Laravel\Mfa\Assurance\Evaluation  $judge
     * @return void
     */
    private function checkProofsWith(\Closure $judge): void
    {
        $this->app?->instance(RequirementCheck::class, new readonly class ($judge) implements RequirementCheck {
            /**
             * Constructor.
             *
             * @param  \Closure(\SineMacula\Laravel\Mfa\Requirements\Requirement, list<\SineMacula\Laravel\Mfa\Proofs\Proof>): \SineMacula\Laravel\Mfa\Assurance\Evaluation  $judge
             */
            public function __construct(

                /** Judges every question. */
                private \Closure $judge,
            ) {}

            /**
             * The evaluation the closure judges.
             *
             * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
             * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
             * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
             */
            #[\Override]
            public function check(MfaRequirement $requirement, Proof ...$proofs): MfaEvaluation
            {
                return ($this->judge)($requirement, array_values($proofs));
            }
        });
    }

    /**
     * The adapter, with the collaborators the container holds now.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\RequirementCheckAdapter
     */
    private function adapter(): RequirementCheckAdapter
    {
        $adapter = $this->app?->make(RequirementCheckAdapter::class);

        self::assertInstanceOf(RequirementCheckAdapter::class, $adapter);

        return $adapter;
    }

    /**
     * The kinds of the proofs, in order.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<\SineMacula\Laravel\Mfa\Enums\ProofKind>
     */
    private static function kinds(array $proofs): array
    {
        return array_map(static fn (Proof $proof): MfaProofKind => $proof->kind, $proofs);
    }

    /**
     * A subject of the identity at sign-in, before its session is written, with
     * a first factor on its password and the further proofs given, newest
     * first.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \Carbon\CarbonImmutable  $now
     * @param  list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>  $further
     * @param  ?\Carbon\CarbonImmutable  $signedInAt
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementSubject
     */
    private static function subject(Identity $identity, CarbonImmutable $now, array $further = [], ?CarbonImmutable $signedInAt = null): RequirementSubject
    {
        return new RequirementSubject($identity, self::GUARD, null, self::firstFactor($signedInAt ?? $now->subMinute()), $now, static fn (): array => $further);
    }

    /**
     * The first factor of a sign-in with the password at the time given.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     */
    private static function firstFactor(CarbonImmutable $at): RecordedProof
    {
        $channel = new Channel(ChannelKind::PASSWORD);

        return new RecordedProof('proof-first', ProofKind::FIRST_FACTOR, Purpose::SIGN_IN, 'password', $channel, null, new ObservedProperties, null, ['pwd'], $at);
    }

    /**
     * A further factor, an authenticator app's code, made with the method given
     * at the time given.
     *
     * @param  string  $method
     * @param  \Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     */
    private static function further(string $method, CarbonImmutable $at): RecordedProof
    {
        $channel = new Channel(ChannelKind::AUTHENTICATOR_APP, self::FACTOR);

        $evaluation = new Evaluation(true, true);

        $id = 'proof-' . $method;

        return new RecordedProof($id, ProofKind::ADDITIONAL_FACTOR, Purpose::SIGN_IN, $method, $channel, self::FACTOR, new ObservedProperties, $evaluation, ['otp'], $at);
    }

    /**
     * Assert that the callback is refused as unresolved, for the kind of
     * reference given, and return the refusal.
     *
     * @param  \SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind  $kind
     * @param  \Closure(): mixed  $callback
     * @return \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function assertUnresolved(ReferenceKind $kind, \Closure $callback): UnresolvedReferenceException
    {
        try {
            $callback();
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame($kind, $exception->kind);

            return $exception;
        }

        self::fail('The reference was resolved.');
    }

    /**
     * Lock the person's MFA identity state and factors on the other connection,
     * and have this one wait only briefly for any lock.
     *
     * @param  \PDO  $other
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return void
     */
    private static function holdMfaRows(\PDO $other, Person $person): void
    {
        foreach (['mfa_identity_states', 'mfa_factors'] as $table) {

            $statement = $other->prepare('select * from ' . $table . ' where authenticatable_type = ? and authenticatable_id = ? for update');

            $statement->execute([$person->getMorphClass(), $person->getKey()]);
        }

        DB::statement(DB::connection()->getDriverName() === 'pgsql'
            ? 'set lock_timeout = \'' . self::LOCK_WAIT_SECONDS . 's\''
            : 'set session innodb_lock_wait_timeout = ' . self::LOCK_WAIT_SECONDS);
    }

    /**
     * A second connection to the test's database, outside Laravel's.
     *
     * @return \PDO
     */
    private static function otherConnection(): \PDO
    {
        /** @var array{driver: string, host: string, port: string, database: string, username: string, password: string} $config */
        $config = Config::get('database.connections.' . self::CONNECTION);

        return new \PDO(
            sprintf('%s:host=%s;port=%s;dbname=%s', $config['driver'], $config['host'], $config['port'], $config['database']),
            $config['username'],
            $config['password'],
            [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION],
        );
    }
}
