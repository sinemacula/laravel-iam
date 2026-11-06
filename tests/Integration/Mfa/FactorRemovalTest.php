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
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\TestCase;

/**
 * Removes a factor through MFA with every adapter between the two members bound
 * by this package's binding rule, as an application gets them, and holds MFA's
 * account of the removal to `laravel-authentication`'s (IAM-3.7, IAM-3.11).
 *
 * MFA deletes the factor, forgets it in the proof store, reads the proofs the
 * session kept and only then reports the removal to the session revoker, whose
 * `factorRemoved()` voids the factor's proofs and judges the session again. The
 * requirement MFA reports outstanding is judged on the proofs it read, so the
 * proof store must already leave the removed factor's proofs out: otherwise MFA
 * reports the requirement met while `laravel-authentication` has returned the
 * session to pending in the same transaction.
 *
 * The identity asks for a further factor made within the last five minutes once
 * it holds a factor. The session steps up with the factor it keeps, then,
 * later, with the one it removes; the removal is allowed on the first step-up,
 * still fresh enough for a factor change, and leaves the session either still
 * meeting the requirement or short of it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofStoreAdapter::class)]
#[CoversClass(SessionRevokerAdapter::class)]
final class FactorRemovalTest extends TestCase
{
    use ArrangesFactorChanges, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var int How old a further factor may be for the identity's requirement, in seconds. */
    private const int MAX_AGE = 300;

    /**
     * How old a further factor may be for the identity's requirement, in
     * seconds.
     *
     * @return int
     */
    public static function maxAge(): int
    {
        return self::MAX_AGE;
    }

    /**
     * Rows of `[seconds between the two step-ups, whether the session is left
     * short of its requirement]`.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideStepUpGaps(): iterable
    {
        yield 'the kept factor\'s step-up is too old' => [self::MAX_AGE + 100, true];

        yield 'the kept factor\'s step-up is fresh enough' => [self::MAX_AGE - 100, false];
    }

    /**
     * The requirement MFA reports outstanding after a removal agrees with the
     * session `laravel-authentication` judged in the same transaction: a
     * session returned to pending has a requirement outstanding, and one kept
     * active has none.
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
     * On MySQL and PostgreSQL, at READ COMMITTED and REPEATABLE READ, the
     * removed factor's proofs stop counting inside MFA's own transaction: a
     * session left short of its requirement is reported so.
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
     * Sign a person in, give them two factors, step the session up with the one
     * kept and, the gap later, with the one removed, then remove it through MFA
     * from the session.
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
     * From now on, have MFA ask an identity that holds a factor, as its own
     * requirement, for a further factor made within `MAX_AGE`, and one that
     * holds none for nothing, so the person signs in active. MFA's requirement
     * policy, which `laravel-authentication` asks through this package, and
     * MFA's judgement of a removal both read it.
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
     * Assert the removal was made and that MFA's account of it agrees with the
     * session `laravel-authentication` judged: pending, with a new pending
     * credential and a requirement outstanding, when the session was left short
     * of it, and otherwise active with none outstanding.
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
