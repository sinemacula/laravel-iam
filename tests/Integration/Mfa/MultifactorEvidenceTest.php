<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Iam\Mfa\FreshnessGateAdapter;
use SineMacula\Laravel\Iam\Mfa\StepUpAdapter;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * A step-up is recorded multifactor only when MFA says it refreshes it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StepUpAdapter::class)]
#[CoversClass(FreshnessGateAdapter::class)]
final class MultifactorEvidenceTest extends TestCase
{
    use ArrangesFactorChanges, MigratesMembers, SignsInPeople;

    /** @var string An operation of MFA's that `laravel-authentication` configures no setting for. */
    private const string OPERATION = 'mfa.remove_factor';

    /** @var int How recent multifactor authentication must be, in seconds. */
    private const int MAX_AGE = 300;

    /** @var string The address the email factor's codes go to. */
    private const string DESTINATION = 'ada@example.test';

    /**
     * A fresh weaker proof never refreshes an old multifactor one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFreshWeakerProofNeverRefreshesAnOldMultifactorOne(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());
        config()->set('mfa.applications.' . self::GUARD . '.types', ['totp', 'email']);

        $this->app?->bind(ChallengeGateway::class, PackageChallengeGateway::class);

        $sender  = FakeEmailSender::fake($this->app);
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $app     = $this->confirmedFactor($person);

        $this->travel(1)->minutes();

        $totp = Mfa::verify(self::servedCaller(), Submission::factor($app->id, AuthenticatorApp::code($app)), Purpose::STEP_UP);

        self::assertTrue($totp->isVerified());
        self::assertTrue($totp->refreshesMultifactor);
        self::assertTrue($this->proofsOf($session)[0]->evaluation?->multifactor);
        self::assertTrue($this->isFreshMultifactor());

        $this->travel(3)->hours();

        $email = $this->stepUpWithAnEmailCode($person, $session, $sender);

        self::assertTrue($email->evaluation?->accepted);
        self::assertFalse($email->evaluation->multifactor);
        self::assertFalse($this->isFreshMultifactorByMfasCheck($person));
        self::assertFalse($this->isFreshMultifactor());
        self::assertTrue($this->gate()->isFresh(self::servedCaller(), self::OPERATION, Requirement::none()->withAdditionalVerification(self::MAX_AGE)));

        self::assertTrue(Mfa::removeFactor(self::servedCaller(), $app->id)->wasMade());
        self::assertNull(Factor::query()->find($app->id));

        self::assertFalse($this->isFreshMultifactorByMfasCheck($person));
        self::assertFalse($this->isFreshMultifactor());
    }

    /**
     * Step the session up with an email code and return its proof.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Mfa\Testing\FakeEmailSender  $sender
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \Throwable
     */
    private function stepUpWithAnEmailCode(Person $person, Session $session, FakeEmailSender $sender): RecordedProof
    {
        $factor = Factor::query()->create([
            'type'                 => 'email',
            'destination'          => self::DESTINATION,
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => ProofOwner::of($person)->key,
            'status'               => FactorStatus::CONFIRMED->value,
            'application'          => self::GUARD,
            'confirmed_at'         => CarbonImmutable::now(),
        ]);

        $sent = Mfa::sendCode(self::servedCaller(), $factor->id, Purpose::STEP_UP);
        $code = $sender->lastCodeTo(self::DESTINATION);

        self::assertIsString($sent->challengeId);
        self::assertIsString($code);
        self::assertTrue(Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, $sent->challengeId, $code), Purpose::STEP_UP)->isVerified());

        foreach ($this->proofsOf($session) as $proof) {
            if ($proof->factor === $factor->id) {
                return $proof;
            }
        }

        self::fail('The email code was not recorded.');
    }

    /**
     * Whether the freshness gate finds the session fresh multifactor.
     *
     * @return bool
     *
     * @throws \Throwable
     */
    private function isFreshMultifactor(): bool
    {
        return $this->gate()->isFresh(self::servedCaller(), self::OPERATION, Requirement::none()->withMultifactor(self::MAX_AGE));
    }

    /**
     * Whether MFA's requirement check finds the session's proofs multifactor.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return bool
     *
     * @throws \Throwable
     */
    private function isFreshMultifactorByMfasCheck(Person $person): bool
    {
        $store   = $this->app?->make(ProofStore::class);
        $current = $store?->currentSession($person, self::GUARD);
        $proofs  = $store === null || $current === null ? [] : $store->proofs($person, self::GUARD, $current);
        $check   = $this->app?->make(RequirementCheck::class);

        self::assertInstanceOf(RequirementCheck::class, $check);

        return $check->check(Requirement::none()->withMultifactor(self::MAX_AGE), ...$proofs)->meetsRequirement();
    }

    /**
     * This package's freshness gate, the one bound over MFA's.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\FreshnessGateAdapter
     */
    private function gate(): FreshnessGateAdapter
    {
        $gate = $this->app?->make(FreshnessGateAdapter::class);

        self::assertInstanceOf(FreshnessGateAdapter::class, $gate);

        return $gate;
    }
}
