<?php

declare(strict_types = 1);

namespace Tests\Performance\Sso;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\SignInRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Performance\PerformanceContractTestCase;

/**
 * Query budget of redeeming a `sign_in` handoff code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInRedemption::class)]
final class SignInRedemptionQueryBudgetTest extends PerformanceContractTestCase
{
    use MigratesSso, RunsSsoFlows, SignsInPeople;

    /**
     * Arrange SSO, and link a person.
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
        $this->linkThroughFlow($this->createPerson());
    }

    /**
     * A linked sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkedSignIn(): void
    {
        $handoff = $this->handoff();

        // Reads: SSO 5, identity 2, MFA 3, proofs and provenance 3, guard 2.
        // Writes: SSO 5, authentication 4; one transaction, 4 savepoints.
        $context = new SignInContext(self::client());
        $redeem  = fn (): RedemptionResult|SignInResult => Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, $context);
        $answer  = $this->assertQueryBudget(15, 9, $redeem, begins: 5, commits: 5);

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn());
    }

    /**
     * A refusal by SSO, of a code it does not know.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalOfAnUnknownCode(): void
    {
        // Reads the code, counts the attempt, and commits the refusal.
        $context = new SignInContext(self::client());
        $redeem  = fn (): RedemptionResult|SignInResult => Iam::signIns()->redeem(self::GUARD, $this->connectionId, str_repeat('A', 43), str_repeat('B', 43), $context);
        $answer  = $this->assertQueryBudget(1, 1, $redeem, begins: 1, commits: 1);

        self::assertInstanceOf(RedemptionResult::class, $answer);
        self::assertTrue($answer->isRefused());
    }
}
