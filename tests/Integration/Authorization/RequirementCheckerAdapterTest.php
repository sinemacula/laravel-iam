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
use SineMacula\Laravel\Iam\Mfa\SignInProofs;
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
 * Integration tests for `laravel-authorization`'s requirement checker, answered
 * by MFA's requirement check on the proofs of the subject's own session
 * (IAM-6.3): a requirement is unmet until the session steps up through MFA and
 * met once it has, until a maximum age bounds it; each part is judged as MFA
 * judges it; the proofs of another identity's session, and of the subject's
 * other sessions, never count; the session must act in the subject's tenant,
 * named in `laravel-authentication`'s terms or `laravel-authorization`'s; a
 * session no longer live meets nothing; whatever cannot be resolved or judged
 * is refused by throwing, which `laravel-authorization` reads as undecidable;
 * and inside a transaction the proofs are read current, so a factor removal
 * committed after the transaction's first read shows.
 *
 * Each scenario that reads stored proofs runs at the connection's own level on
 * every engine, then at READ COMMITTED and REPEATABLE READ on MySQL and
 * PostgreSQL.
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
     * The requirement is unmet until the session steps up through MFA, and met
     * once it has, with no instant it stops being met while no maximum age
     * bounds it.
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
     * A maximum age bounds the answer: met until the step-up is that old, and
     * unmet once it is older.
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
     * Each part is judged as MFA judges it: an authenticator app meets an
     * additional verification, multifactor authentication and AAL2, but no
     * phishing resistance and no AAL3, and the parts left unmet are named as
     * `laravel-authorization` names them.
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
     * The proofs judged are the subject's own: the subject's other session,
     * never stepped up, meets nothing, and another identity's session is never
     * judged, whether the subject names its key or a principal acting for
     * another identity names it.
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
     * A subject that is not a principal is judged only on its own session: one
     * paired with another identity's stepped-up session, whether a model of its
     * own or an object that is no identity at all, is refused, and never meets
     * that identity's requirement on that identity's proofs.
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

        $this->assertRefused(ReferenceKind::SESSION, new Subject($someone, $person, null, self::GUARD, self::GUARD, $key));
        $this->assertRefused(ReferenceKind::SESSION, new Subject(new \stdClass, $person, null, self::GUARD, self::GUARD, $key));
        $this->assertRefused(ReferenceKind::SESSION, new Subject((new Machine)->forceFill(['id' => 7]), $person, null, self::GUARD, self::GUARD, $key));
    }

    /**
     * The session must act in the subject's tenant: a stepped-up session acting
     * in no tenant answers for no subject in one, and a tenant that cannot be
     * compared is refused; once the session acts in the tenant, named by an
     * integer or by text, it answers for the subject in it, and for no subject
     * in none.
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
     * A tenant in `laravel-authorization`'s own terms is read as it reads one,
     * by its key: its `Reference`, which a listing in a scope puts on the
     * request's subject, and a model of the application's, each answer for the
     * subject in the session's tenant and are refused in another; a reference
     * naming no key, a model not yet stored, and a tenant of
     * `laravel-authentication`'s naming itself by no string or integer cannot
     * be read, and are refused.
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
     * An identity MFA reads as inactive meets no requirement, as MFA's own
     * route gate has it: a person deactivated after stepping up meets nothing
     * on the proofs made before, and meets the requirement again once active.
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
     * What cannot be resolved is refused by throwing: a subject with no session
     * (which `laravel-authorization` never hands the checker) or no guard, an
     * identity MFA cannot hold factors for, a guard
     * that holds no sessions and a key naming no session of the identity's;
     * and so is a level MFA does not know, before anything is read.
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
     * A principal that is not its identity is judged on the session of the
     * identity it acts for, where the subject names none, and refused where the
     * subject names another identity, whose session it never judges; so is a
     * principal that is a model of its own, by the identity it acts for, not by
     * itself.
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
     * The proofs reach MFA's check after the first factor, oldest first, as
     * MFA's own requirement check is handed them: the readers return the
     * further proofs newest first.
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
     * The checker's answer depends on the subject's session alone, so it is
     * scope invariant, and a statement stating a requirement compiles in a
     * query scope.
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
     * Inside a transaction the proofs are read current: a removal of the factor
     * committed on another connection after the transaction's first read shows,
     * and the requirement is unmet.
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
            fn () => $this->removeElsewhere($person, $session, SignInProofs::factorReference($factor)),
            fn (): RequirementResult => $this->check(['multifactor' => []], self::subjectOf($person, $session)),
        );

        self::assertEquals(RequirementResult::unmet(['multifactor']), $result);
    }

    /**
     * Ask the bound checker whether the subject's session meets the requirement
     * the operand states.
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
     * Assert asking whether the subject's session is multifactor is refused as
     * unresolvable, of the kind given.
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
     * Resolve the abstract from the application under test, as anything that
     * asks for it does.
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
