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
 * The statements one redemption of a `sign_in` handoff code makes, from the
 * transaction the redemption opens to its commit (IAM-4.1), so a read or a
 * write added to the redemption, by this package or by either member through
 * it, is seen here.
 *
 * A linked sign-in reads and writes what SSO's admission and
 * `laravel-authentication`'s external sign-in each need, and nothing of this
 * package's own beyond the one identity its link contract resolves: the
 * redemption opens one transaction, and each member's work is a savepoint of
 * it. A refusal by SSO of a code it does not know counts the attempt, reads
 * nothing more, and commits.
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

        // Reads (15): SSO's five (the code by its digest, the connection's
        // tenant, then under the locks the connection, the code and the link);
        // the link contract's read of the identity the redemption linked, and
        // laravel-authentication's own; MFA's three for the additional-factor
        // policy (the generation, the factors, the re-enrolment obligation);
        // laravel-authentication's three of the new session's proofs and
        // provenance; and, after the commit, the two the guard binds the
        // session with. Writes (9): SSO's five (the attempt counted, the code
        // recorded as used and consumed, the link's last use, the connection's
        // completed sign-in) and laravel-authentication's four (the link's
        // connection guard, the session, its first proof, its provenance).
        // Transactions: the redemption's, SSO's savepoint and its single-use
        // savepoint, and laravel-authentication's two savepoints, each begun
        // and committed.
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
        // Reads (1): the code by its digest. Writes (1): the attempt counted.
        // Transactions: the redemption's, begun and committed with the refusal.
        $context = new SignInContext(self::client());
        $redeem  = fn (): RedemptionResult|SignInResult => Iam::signIns()->redeem(self::GUARD, $this->connectionId, str_repeat('A', 43), str_repeat('B', 43), $context);
        $answer  = $this->assertQueryBudget(1, 1, $redeem, begins: 1, commits: 1);

        self::assertInstanceOf(RedemptionResult::class, $answer);
        self::assertTrue($answer->isRefused());
    }
}
