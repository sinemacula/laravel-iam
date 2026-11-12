<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\FactorRemoval;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter;
use SineMacula\Laravel\Iam\Mfa\SignInProofs;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Tests that MFA's account of a factor removal agrees with the session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofStoreAdapter::class)]
#[CoversClass(SignInProofs::class)]
#[CoversClass(SessionRevokerAdapter::class)]
final class FactorRemovalTest extends TestCase
{
    use ArrangesFactorChanges, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var int How old a further factor may be for the identity's requirement, in seconds. */
    private const int MAX_AGE = 300;

    /**
     * How old a further factor may be, in seconds.
     *
     * @return int
     */
    public static function maxAge(): int
    {
        return self::MAX_AGE;
    }

    /**
     * Rows of `[seconds between the two step-ups, whether the session is left short of its requirement]`.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideStepUpGaps(): iterable
    {
        yield 'the kept factor\'s step-up is too old' => [self::MAX_AGE + 100, true];

        yield 'the kept factor\'s step-up is fresh enough' => [self::MAX_AGE - 100, false];
    }

    /**
     * The requirement MFA reports outstanding agrees with the judged session.
     *
     * @param  int  $gap
     * @param  bool  $short
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideStepUpGaps')]
    public function testTheOutstandingRequirementAgreesWithTheJudgedSession(int $gap, bool $short): void
    {
        [$session, $removed, $result] = $this->removeAfterSteppingUp($gap);

        self::assertRemovalAgrees($result, $short);
        self::assertSame($short ? SessionStatus::PENDING : SessionStatus::ACTIVE, Session::query()->whereKey($session->getKey())->firstOrFail()->getStatus());
        self::assertNull(Factor::query()->find($removed->id));
    }

    /**
     * The removed factor's proof stops counting; the kept one's still counts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRemovedFactorsProofNoLongerCountsOnTheSession(): void
    {
        [$session, $removed, $result] = $this->removeAfterSteppingUp(self::MAX_AGE - 100);

        self::assertTrue($result->wasMade());

        $person = Person::query()->sole();
        $proofs = $this->app?->make(ProofStoreAdapter::class)->proofs($person, self::GUARD, $this->signInReference($session)) ?? self::fail('The application has not booted.');
        $names  = array_map(static fn (Proof $proof): ?string => $proof->reference, $proofs);

        self::assertCount(2, $names);
        self::assertNotContains($removed->id, $names);
    }

    /**
     * The removed factor stops counting inside MFA's own transaction.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testTheRemovedFactorStopsCountingInsideMfasTransaction(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$session, , $result] = $this->removeAfterSteppingUp(self::MAX_AGE + 100);

        self::assertRemovalAgrees($result, true);
        self::assertSame(SessionStatus::PENDING, Session::query()->whereKey($session->getKey())->firstOrFail()->getStatus());
        self::assertSame(0, self::storage()->transactionLevel());
    }

    /**
     * Step up with each factor, then remove the second through MFA.
     *
     * @param  int  $gap
     * @return array{0: \SineMacula\Laravel\Authentication\Models\Session, 1: \SineMacula\Laravel\Mfa\Models\Factor, 2: \SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult}
     *
     * @throws \Throwable
     */
    private function removeAfterSteppingUp(int $gap): array
    {
        $this->requireARecentFurtherFactor();

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        self::assertInstanceOf(Session::class, $session);
        self::assertSame(SessionStatus::ACTIVE, $session->getStatus());

        [$removed, $kept] = [$this->confirmedFactor($person), $this->confirmedFactor($person)];

        $this->stepUpWith($person, $session, $kept->id);
        $this->travel($gap)->seconds();
        $this->stepUpWith($person, $session, $removed->id);

        return [$session, $removed, Mfa::removeFactor(self::servedCaller(), $removed->id)];
    }

    /**
     * Have MFA ask for a further factor made within `MAX_AGE`.
     *
     * @return void
     */
    private function requireARecentFurtherFactor(): void
    {
        $this->app?->instance(IdentityRequirement::class, new class implements IdentityRequirement {
            /**
             * Ask an identity holding a factor for a recent further factor.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
             * @param  string  $application
             * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(MultiFactorAuthenticatable $identity, string $application): Requirement
            {
                return $identity->isMfaEnabled() ? Requirement::none()->withAdditionalVerification(FactorRemovalTest::maxAge()) : Requirement::none();
            }
        });
    }

    /**
     * Assert MFA's account of the removal agrees with the judged session.
     *
     * @param  \SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult  $result
     * @param  bool  $short
     * @return void
     */
    private static function assertRemovalAgrees(FactorRemovalResult $result, bool $short): void
    {
        self::assertTrue($result->wasMade(), sprintf('The removal was refused: [%s].', $result->reason->value ?? 'none'));

        $completion = $result->completion();

        self::assertInstanceOf(FactorRemoval::class, $completion);
        self::assertSame($short, $completion->isPending());
        self::assertSame($short, $completion->credential !== null);
        self::assertSame($short, $result->outstanding !== null, 'MFA\'s outstanding requirement disagrees with the session laravel-authentication judged.');
        self::assertSame($short, $result->outstanding?->asks(RequirementPart::ADDITIONAL_VERIFICATION) ?? false);
        self::assertSame($short ? self::MAX_AGE : null, $result->outstanding?->maxAge(RequirementPart::ADDITIONAL_VERIFICATION));
    }
}
