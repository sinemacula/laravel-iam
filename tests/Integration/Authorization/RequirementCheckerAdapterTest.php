<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\RequirementCheckerAdapter;
use SineMacula\Laravel\Iam\Authorization\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator;
use SineMacula\Laravel\Iam\Testing\Concerns\InteractsWithIam;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;
use Tests\Concerns\ChangesSessionsElsewhere;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Machine;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for the requirement checker answered by MFA.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementCheckerAdapter::class)]
#[CoversClass(RequirementTranslator::class)]
final class RequirementCheckerAdapterTest extends TestCase
{
    use ChangesSessionsElsewhere, InteractsWithIam, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /**
     * A requirement is unmet until the session steps up.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARequirementIsUnmetUntilTheSessionStepsUp(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        self::assertEquals(RequirementResult::unmet(['multifactor']), $this->check(['multifactor' => []], self::subjectOf($person, $session)));

        $this->actingOnVerifiedSession($session);

        self::assertEquals(RequirementResult::met(), $this->check(['multifactor' => []], self::subjectOf($person, $session)));
    }

    /**
     * A maximum age bounds the answer.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMaximumAgeBoundsTheAnswer(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->freezeSecond();

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);

        $met = $this->check(['multifactor' => ['max_age' => 600]], self::subjectOf($person, $session));

        self::assertTrue($met->isMet);
        self::assertEquals(CarbonImmutable::now()->addSeconds(600), $met->metUntil);

        $this->travel(601)->seconds();

        self::assertEquals(RequirementResult::unmet(['multifactor']), $this->check(['multifactor' => ['max_age' => 600]], self::subjectOf($person, $session)));
    }

    /**
     * Each part is judged as MFA judges it.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testEachPartIsJudgedAsMfaJudgesIt(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);

        $subject = self::subjectOf($person, $session);

        $aal2 = ['additional_verification' => [], 'multifactor' => [], 'assurance_level' => ['min' => 'aal2']];
        $aal3 = ['phishing_resistant' => [], 'assurance_level' => ['min' => 'aal3']];

        self::assertEquals(RequirementResult::met(), $this->check($aal2, $subject));
        self::assertEquals(RequirementResult::unmet(['phishing_resistant']), $this->check(['additional_verification' => [], 'phishing_resistant' => []], $subject));
        self::assertEquals(RequirementResult::unmet(['phishing_resistant', 'assurance_level']), $this->check($aal3, $subject));
    }

    /**
     * Only the subject's own session is judged.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testOnlyTheSubjectsOwnSessionIsJudged(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $other   = $this->signIn($person)->record;
        $session = $this->signInAndActOnSession($person);
        $someone = $this->createPerson();

        $this->actingOnVerifiedSession($session);

        self::assertEquals(RequirementResult::unmet(['multifactor']), $this->check(['multifactor' => []], self::subjectOf($person, $other)));

        $this->assertRefused(ReferenceKind::SESSION, self::subjectOf($someone, $session));
        $this->assertRefused(ReferenceKind::SESSION, new Subject($someone, $person, null, self::GUARD, self::GUARD, self::keyOf($session)));
    }

    /**
     * A subject paired with another identity's session is refused.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testASubjectPairedWithAnotherIdentitysSessionIsRefused(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $someone = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $key     = self::keyOf($session);

        $this->actingOnVerifiedSession($session);

        self::assertEquals(RequirementResult::met(), $this->check(['multifactor' => []], new Subject($person, null, null, self::GUARD, self::GUARD, $key)));
        self::assertEquals(RequirementResult::met(), $this->check(['multifactor' => []], new Subject(clone $person, $person, null, self::GUARD, self::GUARD, $key)));

        $this->assertRefused(ReferenceKind::SESSION, new Subject($someone, $person, null, self::GUARD, self::GUARD, $key));
        $this->assertRefused(ReferenceKind::SESSION, new Subject(new \stdClass, $person, null, self::GUARD, self::GUARD, $key));
        $this->assertRefused(ReferenceKind::SESSION, new Subject((new Machine)->forceFill(['id' => 7]), $person, null, self::GUARD, self::GUARD, $key));
    }

    /**
     * The session must act in the subject's tenant.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheSessionMustActInTheSubjectsTenant(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $key     = self::keyOf($session);

        $this->actingOnVerifiedSession($session);

        self::assertNull($session->getTenantId());

        $this->assertRefused(ReferenceKind::SESSION, new Subject($person, $person, self::tenant(7), self::GUARD, self::GUARD, $key));
        $this->assertRefused(ReferenceKind::SESSION, new Subject($person, $person, new \stdClass, self::GUARD, self::GUARD, $key));

        $session->forceFill([$session->getTenantIdName() => '7'])->save();

        self::assertEquals(RequirementResult::met(), $this->check(['multifactor' => []], new Subject($person, $person, self::tenant(7), self::GUARD, self::GUARD, $key)));
        self::assertEquals(RequirementResult::met(), $this->check(['multifactor' => []], new Subject($person, $person, self::tenant('7'), self::GUARD, self::GUARD, $key)));

        $this->assertRefused(ReferenceKind::SESSION, new Subject($person, $person, null, self::GUARD, self::GUARD, $key));
        $this->assertRefused(ReferenceKind::SESSION, new Subject($person, $person, self::tenant(8), self::GUARD, self::GUARD, $key));
    }

    /**
     * A tenant in authorization's terms is read by its key.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testATenantInLaravelAuthorizationsTermsIsReadByItsKey(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $key     = self::keyOf($session);

        $this->actingOnVerifiedSession($session);

        $session->forceFill([$session->getTenantIdName() => '7'])->save();

        $model = (new Machine)->forceFill(['id' => 7]);

        $reference = new Reference('tenant', '7');

        self::assertEquals(RequirementResult::met(), $this->check(['multifactor' => []], new Subject($person, $person, $reference, self::GUARD, self::GUARD, $key)));
        self::assertEquals(RequirementResult::met(), $this->check(['multifactor' => []], new Subject($person, $person, $model, self::GUARD, self::GUARD, $key)));

        $this->assertRefused(ReferenceKind::SESSION, new Subject($person, $person, new Reference('tenant', '8'), self::GUARD, self::GUARD, $key));
        $this->assertRefused(ReferenceKind::SESSION, new Subject($person, $person, new Reference('tenant', ''), self::GUARD, self::GUARD, $key));
        $this->assertRefused(ReferenceKind::SESSION, new Subject($person, $person, new Machine, self::GUARD, self::GUARD, $key));
        $this->assertRefused(ReferenceKind::SESSION, new Subject($person, $person, self::tenant(7.0), self::GUARD, self::GUARD, $key));
    }

    /**
     * An inactive identity meets no requirement.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnInactiveIdentityMeetsNoRequirement(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);

        self::assertEquals(RequirementResult::met(), $this->check(['multifactor' => []], self::subjectOf($person, $session)));

        $person->forceFill(['is_active' => false])->save();

        $subject = self::subjectOf($person, $session);
        $strong  = ['additional_verification' => [], 'phishing_resistant' => []];

        self::assertEquals(RequirementResult::unmet(['multifactor']), $this->check(['multifactor' => []], $subject));
        self::assertEquals(RequirementResult::unmet(['additional_verification', 'phishing_resistant']), $this->check($strong, $subject));

        $person->forceFill(['is_active' => true])->save();

        self::assertEquals(RequirementResult::met(), $this->check(['multifactor' => []], self::subjectOf($person, $session)));
    }

    /**
     * A session no longer live meets nothing, though it stepped up.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testASessionNoLongerLiveMeetsNothing(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);

        $this->sessions()->revokeSession($person, $session->getKey(), RevocationReason::REVOKED);

        self::assertEquals(RequirementResult::unmet(['additional_verification']), $this->check(['additional_verification' => []], self::subjectOf($person, $session)));
    }

    /**
     * What cannot be resolved or judged is refused.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testWhatCannotBeResolvedOrJudgedIsRefused(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $key     = self::keyOf($session);
        $machine = new Machine;

        $this->assertRefused(ReferenceKind::SESSION, new Subject($person, $person, null, self::GUARD, self::GUARD));
        $this->assertRefused(ReferenceKind::GUARD, new Subject($person, $person, null, self::GUARD, null, $key));
        $this->assertRefused(ReferenceKind::IDENTITY, new Subject(new \stdClass, null, null, self::GUARD, self::GUARD, $key));
        $this->assertRefused(ReferenceKind::GUARD, new Subject($person, $person, null, 'web', 'web', $key));
        $this->assertRefused(ReferenceKind::SESSION, new Subject($machine, $machine, null, self::GUARD, self::GUARD, $key));
        $this->assertRefused(ReferenceKind::SESSION, new Subject($person, $person, null, self::GUARD, self::GUARD, 'not-a-session'));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The assurance level [gold] is not one MFA can require');

        $this->check(['assurance_level' => ['min' => 'gold']], self::subjectOf($person, $session));
    }

    /**
     * A principal is judged on the identity it acts for.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAPrincipalIsJudgedOnTheIdentityItActsFor(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person    = $this->createPerson();
        $other     = $this->createPerson();
        $session   = $this->signInAndActOnSession($person);
        $key       = self::keyOf($session);
        $principal = self::createStub(Principal::class);

        $principal->method('getIdentity')->willReturn($person);

        self::assertEquals(RequirementResult::unmet(['multifactor']), $this->check(['multifactor' => []], new Subject($principal, null, null, self::GUARD, self::GUARD, $key)));

        $this->assertRefused(ReferenceKind::SESSION, new Subject($principal, $other, null, self::GUARD, self::GUARD, $key));

        $model = self::createStubForIntersectionOfInterfaces([Principal::class, Authenticatable::class]);

        $model->method('getIdentity')->willReturn($person);
        $model->method('getAuthIdentifier')->willReturn('a-principal-of-its-own');

        self::assertEquals(RequirementResult::unmet(['multifactor']), $this->check(['multifactor' => []], new Subject($model, null, null, self::GUARD, self::GUARD, $key)));
    }

    /**
     * The proofs reach MFA after the first factor, oldest first.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheProofsReachMfaAfterTheFirstFactorOldestFirst(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->freezeSecond();

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);
        $this->travel(10)->seconds();
        $this->actingOnVerifiedSession($session);

        $check  = $this->resolved(RequirementCheck::class);
        $judged = new class {
            /** @var list<array{0: \SineMacula\Laravel\Mfa\Enums\ProofKind, 1: int}> The kind and time of each proof judged, in the order MFA was handed them. */
            public array $proofs = [];
        };

        self::assertInstanceOf(RequirementCheck::class, $check);

        $recording = self::createStub(RequirementCheck::class);

        $recording->method('check')->willReturnCallback(static function (MfaRequirement $requirement, Proof ...$proofs) use ($check, $judged): Evaluation {

            foreach ($proofs as $proof) {
                $judged->proofs[] = [$proof->kind, $proof->provedAt->getTimestamp()];
            }

            return $check->check($requirement, ...$proofs);
        });

        $this->app?->instance(RequirementCheck::class, $recording);

        self::assertTrue($this->check(['multifactor' => []], self::subjectOf($person, $session))->isMet);

        $now = CarbonImmutable::now()->getTimestamp();

        self::assertSame(
            [[ProofKind::FIRST_FACTOR, $now - 10], [ProofKind::ADDITIONAL_FACTOR, $now - 10], [ProofKind::ADDITIONAL_FACTOR, $now]],
            $judged->proofs,
        );
    }

    /**
     * The checker is scope invariant.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheCheckerIsScopeInvariant(): void
    {
        self::assertInstanceOf(ScopeInvariant::class, $this->resolved(AuthenticationRequirementChecker::class));
    }

    /**
     * Inside a transaction the proofs are read current.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testInsideATransactionTheProofsAreReadCurrent(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->actingOnVerifiedSession($session);

        $factor = $person->authFactors()->first();

        self::assertInstanceOf(Factor::class, $factor);
        self::assertTrue($this->check(['multifactor' => []], self::subjectOf($person, $session))->isMet);

        $result = $this->askedAfter(
            $level,
            fn () => $this->removeElsewhere($person, $session, CodeTranslator::reference($factor)),
            fn (): RequirementResult => $this->check(['multifactor' => []], self::subjectOf($person, $session)),
        );

        self::assertEquals(RequirementResult::unmet(['multifactor']), $result);
    }

    /**
     * Ask the bound checker about the operand's requirement.
     *
     * @param  array<string, array<string, int|string>>  $operand
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementResult
     *
     * @throws \Throwable
     */
    private function check(array $operand, Subject $subject): RequirementResult
    {
        $checker = $this->resolved(AuthenticationRequirementChecker::class);

        self::assertInstanceOf(RequirementCheckerAdapter::class, $checker);

        return $checker->check(AuthenticationRequirement::fromOperand($operand), $subject);
    }

    /**
     * The person as the subject of a check, signed in with the session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private static function subjectOf(Person $person, EloquentSession&Model $session): Subject
    {
        return new Subject($person, $person, null, self::GUARD, self::GUARD, self::keyOf($session));
    }

    /**
     * The session's key, as `laravel-authorization`'s subject names it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @return string
     */
    private static function keyOf(Model $session): string
    {
        $key = $session->getKey();

        self::assertTrue(is_string($key) || is_int($key));

        return (string) $key;
    }

    /**
     * A tenant of `laravel-authentication`'s, named by the identifier given.
     *
     * @param  mixed  $identifier
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    private static function tenant(mixed $identifier): Tenant
    {
        $tenant = self::createStub(Tenant::class);

        $tenant->method('getTenantIdentifier')->willReturn($identifier);

        return $tenant;
    }

    /**
     * Assert the multifactor question is refused as unresolvable.
     *
     * @param  \SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind  $kind
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return void
     *
     * @throws \Throwable
     */
    private function assertRefused(ReferenceKind $kind, Subject $subject): void
    {
        try {
            $this->check(['multifactor' => []], $subject);
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame($kind, $exception->kind);

            return;
        }

        self::fail('The question was answered.');
    }

    /**
     * Resolve the abstract from the application under test.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }
}
