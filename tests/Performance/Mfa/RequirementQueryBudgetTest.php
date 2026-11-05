<?php

declare(strict_types = 1);

namespace Tests\Performance\Mfa;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Iam\Mfa\AdditionalFactorPolicyAdapter;
use SineMacula\Laravel\Iam\Mfa\RequirementCheckAdapter;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Performance\PerformanceContractTestCase;

/**
 * The statements one requirement judgement makes through the adapters between
 * `laravel-authentication` and MFA (IAM-3.1, IAM-3.2), each asked as
 * `laravel-authentication` asks it on every sign-in and every judgement of a
 * session, so a read added to either path is seen here.
 *
 * Judging the proofs reads the identity's verification generation, once, and
 * nothing else of its own: the proofs are the subject's, read by
 * `laravel-authentication` in the one bounded query it makes (in memory at
 * sign-in, as here), and MFA's default check judges them in memory. Asking the
 * policy reads the generation, once, and then what MFA's default policy reads
 * to compose its answer: the identity's factors and its re-enrolment
 * obligation. Neither writes, opens a transaction or takes a lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementCheckAdapter::class)]
#[CoversClass(AdditionalFactorPolicyAdapter::class)]
final class RequirementQueryBudgetTest extends PerformanceContractTestCase
{
    use MigratesMembers, SignsInPeople;

    /**
     * Judging a sign-in's proofs reads the generation, and nothing else.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testJudgingTheProofsReadsTheGenerationOnly(): void
    {
        $person  = $this->createPerson();
        $now     = CarbonImmutable::now()->startOfSecond();
        $channel = new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor');
        $proved  = new Evaluation(true, true);
        $further = [new RecordedProof('proof-further', ProofKind::ADDITIONAL_FACTOR, Purpose::SIGN_IN, 'totp', $channel, 'factor', new ObservedProperties, $proved, ['otp'], $now)];
        $subject = new RequirementSubject($person, self::GUARD, null, self::firstFactor($now->subMinute()), $now, static fn (): array => $further);
        $check   = $this->check();

        $evaluation = $this->assertQueryBudget(1, 0, static fn (): RequirementEvaluation => $check->evaluate($subject, new Requirement(new RequirementPart(300))));

        self::assertSame([], $evaluation->unmet);
    }

    /**
     * Judging an active session's proofs reads the generation, and nothing
     * else, however many parts the requirement asks for: the session names the
     * sign-in in memory, and its proofs are the subject's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testJudgingASessionsProofsReadsTheGenerationOnly(): void
    {
        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;
        $now     = CarbonImmutable::now()->startOfSecond();
        $channel = new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor');
        $proved  = new Evaluation(true, true);
        $further = [new RecordedProof('proof-further', ProofKind::ADDITIONAL_FACTOR, Purpose::STEP_UP, 'totp', $channel, 'factor', new ObservedProperties, $proved, ['otp'], $now)];
        $subject = new RequirementSubject($person, self::GUARD, $session, self::firstFactor($now->subMinute()), $now, static fn (): array => $further);
        $check   = $this->check();
        $asked   = new Requirement(new RequirementPart(300), new RequirementPart(600), null, new RequirementPart);

        $evaluation = $this->assertQueryBudget(1, 0, static fn (): RequirementEvaluation => $check->evaluate($subject, $asked));

        self::assertSame([RequirementKind::PHISHING_RESISTANCE], $evaluation->unmet);
    }

    /**
     * Asking the policy reads the generation, the identity's factors and its
     * re-enrolment obligation.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAskingThePolicyReadsTheGenerationAndWhatMfaComposesItsAnswerFrom(): void
    {
        $person  = $this->createPerson();
        $context = new AdditionalFactorContext(self::GUARD, $person, self::firstFactor(CarbonImmutable::now()), new ClientContext('127.0.0.1', 'tests'), null, null, null);
        $policy  = $this->app?->make(AdditionalFactorPolicyAdapter::class);

        self::assertInstanceOf(AdditionalFactorPolicyAdapter::class, $policy);

        $requirement = $this->assertQueryBudget(3, 0, static fn (): Requirement => $policy->requirementFor($context));

        self::assertTrue($requirement->isEmpty());
    }

    /**
     * The requirement check adapter, resolved from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\RequirementCheckAdapter
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function check(): RequirementCheckAdapter
    {
        $check = $this->app?->make(RequirementCheckAdapter::class);

        self::assertInstanceOf(RequirementCheckAdapter::class, $check);

        return $check;
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
}
