<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Iam\Mfa\SignInProofs;
use SineMacula\Laravel\Iam\Testing\Concerns\InteractsWithIam;
use SineMacula\Laravel\Mfa\Contracts\Factor as FactorContract;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for a session's recorded proofs read as MFA's proofs of the
 * sign-in (IAM-3.11, IAM-3.12): proofs that name no factor are all kept, in the
 * order handed in, without MFA's factor table being read; a proof naming a
 * factor the identity still holds is kept; one naming a factor since removed is
 * left out, and what is kept is a list; and a factor is named by its identifier
 * as text.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInProofs::class)]
final class SignInProofsTest extends TestCase
{
    use InteractsWithIam, MigratesMembers, SignsInPeople;

    /**
     * Proofs that name no factor are each kept, in the order handed in, and
     * MFA's factor table is not read for them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testProofsNamingNoFactorAreAllKeptWithoutReadingTheFactors(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $first   = $this->firstFactorOf($session) ?? self::fail('No first factor was recorded.');
        $table   = (new Factor)->getTable();
        $reads   = 0;

        DB::listen(static function (QueryExecuted $query) use ($table, &$reads): void {
            if (!str_contains($query->sql, $table)) {
                return;
            }

            $reads++;
        });

        $proofs = $this->signInProofs()->of($person, self::GUARD, $session, [$first, $first]);

        self::assertSame([0, 1], array_keys($proofs));
        self::assertSame([null, null], array_map(static fn (Proof $proof): ?string => $proof->reference, $proofs));
        self::assertSame(0, $reads);
    }

    /**
     * A proof naming a factor the identity still holds is kept beside the
     * proofs that name none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofOfAFactorStillHeldIsKept(): void
    {
        $person  = $this->createPerson();
        $session = $this->verifiedSessionOf($person);

        $proofs = $this->signInProofs()->of($person, self::GUARD, $session, [$this->firstOf($session), $this->furtherOf($session)]);

        self::assertSame([null, $this->factorOf($person)], array_map(static fn (Proof $proof): ?string => $proof->reference, $proofs));
    }

    /**
     * A proof naming a factor since removed is left out, whether or not a proof
     * naming no factor is handed in beside it, and what is kept is a list.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofOfAFactorNoLongerHeldIsLeftOut(): void
    {
        $person  = $this->createPerson();
        $session = $this->verifiedSessionOf($person);
        $first   = $this->firstOf($session);
        $further = $this->furtherOf($session);

        Factor::query()->whereKey($this->factorOf($person))->delete();

        $proofs = $this->signInProofs()->of($person, self::GUARD, $session, [$further, $first]);

        self::assertSame([0], array_keys($proofs));
        self::assertNull($proofs[0]->reference);
        self::assertSame([], $this->signInProofs()->of($person, self::GUARD, $session, [$further]));
    }

    /**
     * A factor is named by its identifier as text, so a factor identified by a
     * number is the one a proof naming that number names; an identifier that is
     * no scalar names nothing.
     *
     * @return void
     */
    public function testAFactorIsNamedByItsIdentifierAsText(): void
    {
        $numbered = self::createStub(FactorContract::class);
        $unnamed  = self::createStub(FactorContract::class);

        $numbered->method('getFactorIdentifier')->willReturn(42);
        $unnamed->method('getFactorIdentifier')->willReturn(['42']);

        self::assertSame('42', SignInProofs::factorReference($numbered));
        self::assertSame('', SignInProofs::factorReference($unnamed));
    }

    /**
     * The proofs of the sign-in, as the container builds them.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\SignInProofs
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function signInProofs(): SignInProofs
    {
        return $this->app?->make(SignInProofs::class) ?? self::fail('The application has not booted.');
    }

    /**
     * Sign the person in and verify the session with a further factor.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function verifiedSessionOf(Person $person): EloquentSession&Model
    {
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);

        return $session;
    }

    /**
     * The session's first-factor proof.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \Throwable
     */
    private function firstOf(EloquentSession&Model $session): RecordedProof
    {
        return $this->firstFactorOf($session) ?? self::fail('No first factor was recorded.');
    }

    /**
     * The session's further-factor proof.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \Throwable
     */
    private function furtherOf(EloquentSession&Model $session): RecordedProof
    {
        foreach ($this->proofsOf($session) as $proof) {
            if ($proof->kind === ProofKind::ADDITIONAL_FACTOR) {
                return $proof;
            }
        }

        self::fail('No further proof was recorded.');
    }

    /**
     * The person's factor, as a proof made with it names it.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return string
     */
    private function factorOf(Person $person): string
    {
        $factor = $person->authFactors()->first();

        self::assertInstanceOf(Factor::class, $factor);

        return SignInProofs::factorReference($factor);
    }
}
