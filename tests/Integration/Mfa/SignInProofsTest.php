<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Iam\Mfa\SignInProofs;
use SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator;
use SineMacula\Laravel\Iam\Testing\Concerns\InteractsWithIam;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for a session's recorded proofs read as MFA's proofs of the
 * sign-in (IAM-3.11).
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
     * Proofs are kept in the order handed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testProofsAreKeptInTheOrderHandedIn(): void
    {
        $person  = $this->createPerson();
        $session = $this->verifiedSessionOf($person);

        $proofs = $this->signInProofs()->of($person, self::GUARD, $session, [$this->furtherOf($session), $this->firstOf($session)]);

        self::assertSame([$this->factorOf($person), null], array_map(static fn (Proof $proof): ?string => $proof->reference, $proofs));
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

        return CodeTranslator::reference($factor);
    }
}
