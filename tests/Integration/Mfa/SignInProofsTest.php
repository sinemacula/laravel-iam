<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
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
 * Integration tests for a session's proofs read as MFA's sign-in proofs.
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
     * A read short of the limit is taken whole, oldest first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReadShortOfTheLimitIsTakenWholeOldestFirst(): void
    {
        $session = $this->verifiedSessionOf($this->createPerson());
        $first   = $this->firstOf($session);
        $further = $this->furtherOf($session);
        $reads   = [];

        $history = SignInProofs::history(static function (?array $kinds, int $limit) use (&$reads, $first, $further): array {
            $reads[] = [$kinds, $limit];

            return [$further, $first];
        });

        self::assertSame([$first, $further], $history);
        self::assertSame([[null, RequirementSubject::MAX_LIMIT]], $reads);
    }

    /**
     * A full read is taken again kind by kind, oldest first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFullReadIsTakenAgainKindByKind(): void
    {
        $session = $this->verifiedSessionOf($this->createPerson());
        $first   = $this->firstOf($session);
        $further = self::madeAt($this->furtherOf($session), $first->authenticatedAt->subSecond());
        $reads   = [];

        $history = SignInProofs::history(static function (?array $kinds, int $limit) use (&$reads, $first, $further): array {
            $reads[] = [$kinds, $limit];

            return match ($kinds) {
                null                           => array_fill(0, RequirementSubject::MAX_LIMIT, $first),
                [ProofKind::FIRST_FACTOR]      => [$first],
                [ProofKind::ADDITIONAL_FACTOR] => [$further],
                default                        => [],
            };
        });

        $kinds = array_map(static fn (ProofKind $kind): array => [[$kind], RequirementSubject::MAX_LIMIT], array_reverse(ProofKind::cases()));

        self::assertSame([$further, $first], $history);
        self::assertSame([[null, RequirementSubject::MAX_LIMIT], ...$kinds], $reads);
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
     * The proof as if made at the given time.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $proof
     * @param  \Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     */
    private static function madeAt(RecordedProof $proof, CarbonImmutable $at): RecordedProof
    {
        return new RecordedProof(
            $proof->id,
            $proof->kind,
            $proof->purpose,
            $proof->method,
            $proof->channel,
            $proof->factor,
            $proof->observed,
            $proof->evaluation,
            $proof->methods,
            $at,
            $proof->evidence,
        );
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
