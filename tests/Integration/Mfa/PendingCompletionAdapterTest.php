<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind as AuthenticationProofKind;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\PendingCompletionTests;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Concerns\BindsStrayRequests;
use Tests\Concerns\RecordsRequirementDecisions;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Mfa\Pending\Concerns\ArrangesPendingSessions;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for MFA's pending completion through
 * `laravel-authentication`'s `satisfy()` (IAM-3.3): MFA's contract kit, a
 * verified factor activating the pending session or leaving it pending for the
 * caller's client, the session satisfied only as the last write of MFA's
 * transaction (after MFA's locks, rolled back with it, and never answered when
 * its commit fails), a caller holding no pending session refused, the refusals
 * `laravel-authentication` answers thrown as MFA's (a cross-site client's on a
 * guard whose refresh token travels in a cookie among them, as
 * `cross_site_request`), and the references that cannot be resolved thrown
 * (IAM-8.2).
 *
 * The sessions are real ones, signed in with a password through
 * `laravel-authentication`, whose additional-factor policy and requirement
 * check are stand-ins that leave them pending; MFA verifies through its own
 * defaults, with the pending resolver and completion adapters bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingCompletionAdapter::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class PendingCompletionAdapterTest extends TestCase
{
    use ArrangesPendingSessions, BindsStrayRequests, PendingCompletionTests, RecordsRequirementDecisions, RunsAtIsolationLevels;

    /** @var string The detail of a refusal of a proof made for another pending session. */
    private const string NOT_BOUND = 'The proof is not bound to the pending session.';

    /** @var string The origin of the API's own site, which the same-site client presents and is served from. */
    private const string SITE = 'https://api.example.test';

    /** @var string The custom header a cookie guard's same-site client must carry, as the tests configure it. */
    private const string CSRF_HEADER = 'X-Iam-Csrf';

    /** @var string The IP address of the client a completion is handed, unlike the sign-in's. */
    private const string PENDING_IP = '203.0.113.24';

    /** @var string The user agent of the client a completion is handed, unlike the sign-in's. */
    private const string PENDING_AGENT = 'pending-client';

    /** @var ?\SineMacula\Laravel\Mfa\Context\PendingContext The pending session MFA's contract kit is given. */
    private ?PendingContext $arranged = null;

    /**
     * Bind the pending adapters and the stand-ins that leave a sign-in pending.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindPendingSeams();
    }

    /**
     * A verified factor satisfies the pending session inside the transaction,
     * which activates once it commits: the proof is stored with the session's
     * and the guard is bound to it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerifiedFactorActivatesThePendingSession(): void
    {
        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);

        $result = $this->completeInTransaction($pending, $this->verified($pending, $this->factorProof($pending)));

        self::assertInstanceOf(SignInResult::class, $result);
        self::assertTrue($result->isSignedIn());
        self::assertSame($pending->sessionId, $this->signInReference($this->guard()->session() ?? self::fail('The guard was not bound.')));
        self::assertSame(['factor-1'], $this->storedFactors($result));
    }

    /**
     * The decisions `laravel-authorization` keeps for the request are forgotten
     * once the pending session takes the proof (IAM-6.11).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDecisionThatReadThePendingSessionsAuthenticationIsForgotten(): void
    {
        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);

        $this->recordDecision();

        $this->completeInTransaction($pending, $this->verified($pending, $this->factorProof($pending)));

        self::assertNull($this->lastDecision());
    }

    /**
     * A recovery code satisfies the pending session as a further factor does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecoveryCodeActivatesThePendingSession(): void
    {
        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);
        $binding    = $pending->firstFactor->binding;

        $code = new Proof(ProofKind::RECOVERY_CODE, 'recovery_code', null, null, ObservedProperties::none(), CarbonImmutable::now(), $binding, $pending->firstFactor->generation);

        $result = $this->completeInTransaction($pending, $this->verified($pending, $code));

        self::assertInstanceOf(SignInResult::class, $result);
        self::assertTrue($result->isSignedIn());
        self::assertNotNull($result->session);
        self::assertSame([AuthenticationProofKind::RECOVERY_CODE], array_map(
            static fn ($proof): AuthenticationProofKind => $proof->kind,
            array_values(array_filter($this->proofsOf($result->session->record), static fn ($proof): bool => $proof->kind !== AuthenticationProofKind::FIRST_FACTOR)),
        ));
    }

    /**
     * A verified factor that leaves the requirement short keeps the session
     * pending, holding the proof for the rest of it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorThatLeavesTheRequirementShortKeepsTheSessionPending(): void
    {
        $this->bindPendingSeams(2);

        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);

        $result = $this->completeInTransaction($pending, $this->verified($pending, $this->factorProof($pending)));

        self::assertInstanceOf(SignInResult::class, $result);
        self::assertTrue($result->isPending());
        self::assertSame(['factor-1'], array_map(static fn (Proof $proof): ?string => $proof->reference, $this->pendingContextFor($credential)->proofs));
    }

    /**
     * Each proof is recorded accepted, and multifactor only when MFA says it
     * refreshes the multifactor evidence of the first factor, never because of
     * the whole pending session: an email code that completes the sign-in after
     * an authenticator app code is recorded accepted but not multifactor,
     * although MFA's evaluation of the session's proofs together, which the
     * verification carries, is multifactor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachProofIsRecordedWithItsOwnEvaluation(): void
    {
        $this->bindPendingSeams(2);

        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);

        self::assertTrue($this->completeInTransaction($pending, $this->verified($pending, $this->factorProof($pending)))->isPending());

        $pending = $this->pendingContextFor($credential);
        $email   = new Proof(
            ProofKind::ADDITIONAL_FACTOR,
            'email',
            new Channel(ChannelKind::EMAIL, 'ada@example.test'),
            'factor-2',
            ObservedProperties::none(),
            CarbonImmutable::now(),
            $pending->firstFactor->binding,
            $pending->firstFactor->generation,
        );

        $verified = $this->verified($pending, $email);

        self::assertTrue($verified->evaluation?->multifactor);
        self::assertFalse($verified->refreshesMultifactor);

        $result = $this->completeInTransaction($pending, $verified);

        self::assertTrue($result->isSignedIn());
        self::assertNotNull($result->session);

        $flags = [];

        foreach ($this->proofsOf($result->session->record) as $proof) {

            if ($proof->factor === null) {
                continue;
            }

            $flags[$proof->factor] = [$proof->evaluation?->accepted, $proof->evaluation?->multifactor];
        }

        ksort($flags);

        self::assertSame(['factor-1' => [true, true], 'factor-2' => [true, false]], $flags);
    }

    /**
     * The proof an enrolment confirms reaches `laravel-authentication`, which
     * decides whether the session takes it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEnrolmentsProofReachesLaravelAuthentication(): void
    {
        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);

        $result = $this->completeInTransaction($pending, $this->verified($pending, $this->factorProof($pending, Purpose::ENROLLMENT)));

        self::assertInstanceOf(SignInResult::class, $result);
        self::assertTrue($result->isSignedIn());
    }

    /**
     * Rows of `[mismatch]` for the bindings a pending session does not take.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMismatchedBindings(): iterable
    {
        yield 'purpose' => ['purpose'];

        yield 'identity' => ['identity'];

        yield 'identity type' => ['type'];

        yield 'application' => ['application'];

        yield 'sign-in' => ['sign-in'];
    }

    /**
     * A proof for a purpose a pending session cannot take, or bound to another
     * identity, application or sign-in, is refused before anything is read.
     *
     * @param  string  $mismatch
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMismatchedBindings')]
    public function testAProofBoundElsewhereIsRefused(string $mismatch): void
    {
        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);
        $proof      = $this->factorProof($pending);
        $binding    = $proof->binding;

        $elsewhere = match ($mismatch) {
            'purpose'     => $this->factorProof($pending, Purpose::STEP_UP),
            'identity'    => $this->rebound($proof, new ProofBinding($binding->identityType, $binding->identityKey . '0', self::GUARD, $binding->sessionId, $binding->purpose)),
            'type'        => $this->rebound($proof, new ProofBinding('another-type', $binding->identityKey, $binding->application, $binding->sessionId, $binding->purpose)),
            'application' => $this->rebound($proof, new ProofBinding($binding->identityType, $binding->identityKey, 'another-application', $binding->sessionId, $binding->purpose)),
            default       => $this->factorProof($pending, session: 'another-sign-in'),
        };

        self::assertRefused(self::NOT_BOUND, fn (): mixed => $this->completeInTransaction($pending, $this->verified($pending, $elsewhere)));
        self::assertSame([], $this->pendingContextFor($credential)->proofs);
    }

    /**
     * A proof `laravel-authentication` refuses is refused as MFA's refusal,
     * naming its reason for the logs, and writes nothing: here one made before
     * the session began waiting.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofLaravelAuthenticationRefusesIsRefused(): void
    {
        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);
        $proof      = $this->factorProof($pending, provedAt: CarbonImmutable::now()->subHour());

        $result = $this->verified($pending, $proof);

        self::assertRefused('laravel-authentication refused the proof as [proof_invalid].', fn (): mixed => $this->completeInTransaction($pending, $result));
        self::assertSame([], $this->pendingContextFor($credential)->proofs);
        self::assertNull($this->guard()->session());
    }

    /**
     * On a guard whose refresh token travels in a cookie, a completion handed a
     * same-site client (an `Origin` of the API's own site and the guard's
     * configured custom header) passes `laravel-authentication`'s same-site
     * check and activates the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieGuardsSameSiteCompletionIsSatisfied(): void
    {
        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);
        $result     = $this->verified($pending, $this->factorProof($pending));

        self::carryRefreshTokensInACookie();

        $completion = $this->completeInTransaction($pending, $result);

        self::assertTrue($completion->isSignedIn());
        self::assertSame(['factor-1'], $this->storedFactors($completion));
        self::assertSame($pending->sessionId, $this->signInReference($this->guard()->session() ?? self::fail('The guard was not bound.')));
    }

    /**
     * Rows of `[client]` that did not come from a page of the API's own site.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Context\ClientContext}>
     */
    public static function provideCrossSiteClients(): iterable
    {
        yield 'no origin' => [new ClientContext(self::PENDING_IP, self::PENDING_AGENT, null, self::SITE, [self::CSRF_HEADER])];

        yield 'a foreign origin' => [new ClientContext(self::PENDING_IP, self::PENDING_AGENT, 'https://elsewhere.example.test', self::SITE, [self::CSRF_HEADER])];

        yield 'no custom header' => [new ClientContext(self::PENDING_IP, self::PENDING_AGENT, self::SITE, self::SITE, ['X-Requested-With'])];
    }

    /**
     * On a guard whose refresh token travels in a cookie, a completion handed a
     * cross-site client is refused as `not_accepted`, naming
     * `cross_site_request`, by throwing inside MFA's transaction, which rolls
     * back what it wrote before: the session stays pending and the guard
     * unbound, though a request bound in the container carries the very facts
     * the client lacks, since the request is never read in its place.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCrossSiteClients')]
    public function testACookieGuardsCrossSiteCompletionIsRefused(ClientContext $client): void
    {
        $person     = $this->createPerson();
        $credential = $this->signInPending($person);
        $pending    = $this->pendingContextFor($credential);
        $result     = $this->verified($pending, $this->factorProof($pending));

        self::carryRefreshTokensInACookie();

        $this->bindStrayRequest(headers: ['Origin' => 'http://localhost', self::CSRF_HEADER => '1']);

        $completion = function () use ($person, $pending, $client, $result): SignInResult {

            VerificationGeneration::advance($person);

            return $this->pendingCompleter()->complete(CallerContext::forPending($pending, $client), $result);
        };

        self::assertRefused('laravel-authentication refused the proof as [cross_site_request].', static fn (): mixed => DB::transaction($completion));

        self::assertSame(0, VerificationGeneration::current($person));
        self::assertSame([], $this->pendingContextFor($credential)->proofs);
        self::assertNull($this->guard()->session());
    }

    /**
     * The activated session's last use is the client the caller was served
     * from, its IP address and user agent, not the sign-in's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheActivatedSessionsLastUseIsTheCallersClient(): void
    {
        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);

        $result = $this->completeInTransaction($pending, $this->verified($pending, $this->factorProof($pending)));
        $record = $result->session->record ?? self::fail('No session was signed in.');

        self::assertSame(self::PENDING_IP, $record->getAttribute('last_used_ip'));
        self::assertSame(self::PENDING_AGENT, $record->getAttribute('last_used_user_agent'));
    }

    /**
     * A caller holding no pending session is refused as a result bound
     * elsewhere is, though the result is the pending session's and the caller
     * its identity on its application, and nothing is satisfied.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerWithNoPendingSessionIsRefused(): void
    {
        $person     = $this->createPerson();
        $credential = $this->signInPending($person);
        $pending    = $this->pendingContextFor($credential);
        $result     = $this->verified($pending, $this->factorProof($pending));
        $caller     = CallerContext::forIdentity($person, self::GUARD, self::sameSiteClient());

        self::assertRefused('The caller holds no pending session.', fn (): mixed => DB::transaction(fn (): SignInResult => $this->pendingCompleter()->complete($caller, $result)));
        self::assertSame([], $this->pendingContextFor($credential)->proofs);
        self::assertNull($this->guard()->session());
    }

    /**
     * A session already satisfied is no longer pending, so a second completion
     * for it is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASecondCompletionIsRefused(): void
    {
        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);

        $this->completeInTransaction($pending, $this->verified($pending, $this->factorProof($pending)));

        $again = $this->verified($pending, $this->factorProof($pending, factor: 'factor-2'));

        self::assertRefused('laravel-authentication refused the proof as [pending_invalid].', fn (): mixed => $this->completeInTransaction($pending, $again));
    }

    /**
     * A pending context keeping another pending session's credential cannot
     * satisfy this one: `laravel-authentication` refuses the proof's binding,
     * and neither session changes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherPendingSessionsCredentialIsRefused(): void
    {
        $person  = $this->createPerson();
        $other   = $this->signInPending($person);
        $pending = self::keeping($this->pendingContextFor($this->signInPending($person)), $other);
        $result  = $this->verified($pending, $this->factorProof($pending));

        self::assertRefused('laravel-authentication refused the proof as [proof_binding_mismatch].', fn (): mixed => $this->completeInTransaction($pending, $result));
        self::assertSame([], $this->pendingContextFor($other)->proofs);
    }

    /**
     * Without a pending credential on the context, the pending session cannot
     * be resolved, and nothing is satisfied.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAPendingCredentialNothingIsSatisfied(): void
    {
        $credential = $this->signInPending($this->createPerson());
        $pending    = self::keeping($this->pendingContextFor($credential), null);
        $result     = $this->verified($pending, $this->factorProof($pending));

        try {
            $this->completeInTransaction($pending, $result);

            self::fail('A pending session was satisfied without its credential.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::SESSION, $exception->kind);
            self::assertSame(self::GUARD, $exception->application);
            self::assertStringStartsWith('The pending context keeps no pending credential for the guard [api]', $exception->getMessage());
        }

        self::assertSame([], $this->pendingContextFor($credential)->proofs);
    }

    /**
     * The pending session satisfied is the one the context names, on the guard
     * its application names, for the client the caller carries: a request bound
     * in the container, carrying another pending session's credential and
     * coming from another client, names neither the session nor the client, and
     * the default guard being another changes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheHandedContextIsSatisfiedWhateverTheRequestCarries(): void
    {
        $person  = $this->createPerson();
        $pending = $this->pendingContextFor($this->signInPending($person));
        $stray   = $this->signInPending($person);
        $events  = [];

        $this->bindStrayRequest([self::CREDENTIAL_FIELD => $stray]);

        Config::set('auth.defaults.guard', 'web');

        Event::listen(SignedIn::class, static function (SignedIn $event) use (&$events): void {
            $events[] = $event;
        });

        $result = $this->completeInTransaction($pending, $this->verified($pending, $this->factorProof($pending)));

        self::assertTrue($result->isSignedIn());
        $record = $result->session->record ?? self::fail('No session was signed in.');

        self::assertSame($pending->sessionId, $this->signInReference($record));
        self::assertSame(self::PENDING_IP, $record->getAttribute('last_used_ip'));
        self::assertCount(1, $this->sessions()->pending($stray)?->proofs() ?? []);
        self::assertCount(1, $events);
        self::assertSame([self::PENDING_IP, self::PENDING_AGENT], [$events[0]->context->client->ip, $events[0]->context->client->userAgent]);
    }

    /**
     * A context that kept no credential is refused by throwing inside MFA's
     * transaction, which rolls back what it wrote before, though a request
     * bound in the container carries that very session's credential: the
     * request is never read in its place.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutACredentialTheBoundRequestIsNotReadInstead(): void
    {
        $person     = $this->createPerson();
        $credential = $this->signInPending($person);
        $pending    = self::keeping($this->pendingContextFor($credential), null);
        $result     = $this->verified($pending, $this->factorProof($pending));

        $this->bindStrayRequest([self::CREDENTIAL_FIELD => $credential]);

        try {
            DB::transaction(function () use ($person, $pending, $result): SignInResult {

                VerificationGeneration::advance($person);

                return $this->pendingCompleter()->complete(CallerContext::forPending($pending, self::sameSiteClient()), $result);
            });

            self::fail('A pending session was satisfied from the request\'s credential.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::SESSION, $exception->kind);
        }

        self::assertSame(0, VerificationGeneration::current($person));
        self::assertSame([], $this->pendingContextFor($credential)->proofs);
    }

    /**
     * An identity `laravel-authentication` does not sign in cannot be resolved,
     * so its pending session is never satisfied.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityLaravelAuthenticationDoesNotSignInCannotBeResolved(): void
    {
        $stranger = new class extends User implements MultiFactorAuthenticatable {
            use HasFactors;
        };

        $stranger->setAttribute('id', 7);

        $binding = new ProofBinding($stranger->getMorphClass(), '7', self::GUARD, 'stranger-sign-in', Purpose::SIGN_IN);
        $first   = new Proof(ProofKind::FIRST_FACTOR, 'password', new Channel(ChannelKind::PASSWORD), null, ObservedProperties::none(), CarbonImmutable::now(), $binding, 0);
        $expires = CarbonImmutable::now()->addMinutes(5);
        $pending = new PendingContext($stranger, self::GUARD, 'stranger-sign-in', $first, Requirement::none()->withAdditionalVerification(), [], $expires);

        try {
            $this->completeInTransaction($pending, $this->verified($pending, $this->factorProof($pending)));

            self::fail('The pending session of an identity laravel-authentication does not sign in was satisfied.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
            self::assertStringContainsString($stranger::class, $exception->getMessage());
        }
    }

    /**
     * Outside a transaction on the storage connection nothing is satisfied: the
     * session is satisfied only as the last write of MFA's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOutsideATransactionNothingIsSatisfied(): void
    {
        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);

        try {
            $this->pendingCompleter()->complete(CallerContext::forPending($pending, self::sameSiteClient()), $this->verified($pending, $this->factorProof($pending)));

            self::fail('A pending session was satisfied outside a transaction.');
        } catch (\LogicException $exception) {
            self::assertSame('A pending session is satisfied only as the last write of a transaction on the storage connection.', $exception->getMessage());
        }

        self::assertSame([], $this->pendingContextFor($credential)->proofs);
    }

    /**
     * A factor MFA verifies on a pending session activates it through the
     * adapters: MFA's own verification resolves the pending session from the
     * request's credential and hands its proof to `satisfy()`, whose result is
     * MFA's completion.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfaVerifiesAFactorThatActivatesThePendingSession(): void
    {
        $person     = $this->createPerson();
        $factor     = $this->confirmedFactor($person);
        $credential = $this->signInPending($person);

        $result = Mfa::verify(CallerContext::fromRequest(self::requestCarrying($credential)), Submission::factor($factor->getKey(), AuthenticatorApp::code($factor)));

        self::assertTrue($result->isVerified());

        $completion = $result->completion();

        self::assertInstanceOf(SignInResult::class, $completion);
        self::assertTrue($completion->isSignedIn());
        self::assertSame([$factor->id], $this->storedFactors($completion));
    }

    /**
     * The session is satisfied after MFA's locks: the identity's state row is
     * locked before the session's row, at either isolation level.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testTheSessionIsLockedAfterMfasLocks(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person     = $this->createPerson();
        $factor     = $this->confirmedFactor($person);
        $credential = $this->signInPending($person);
        $connection = DB::connection();

        $caller = CallerContext::fromRequest(self::requestCarrying($credential));

        $connection->flushQueryLog();
        $connection->enableQueryLog();

        self::assertTrue(Mfa::verify($caller, Submission::factor($factor->getKey(), AuthenticatorApp::code($factor)))->isVerified());

        $locks = array_values(array_filter(
            array_map(static fn (array $query): string => strtolower($query['query']), $connection->getQueryLog()),
            static fn (string $query): bool => str_contains($query, 'for update'),
        ));

        $identity = self::firstMatching($locks, 'mfa_identity_states');
        $session  = self::firstMatching($locks, 'authentication_sessions');

        self::assertNotNull($identity, 'MFA locked no identity state.');
        self::assertNotNull($session, 'The pending session was never locked.');
        self::assertLessThan($session, $identity, 'The session was locked before MFA\'s identity state.');
    }

    /**
     * A transaction that rolls back after the session was satisfied leaves it
     * pending, its proof unstored and the guard unbound, at either isolation
     * level.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARollbackLeavesTheSessionPending(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);
        $result     = $this->verified($pending, $this->factorProof($pending));

        try {
            DB::transaction(function () use ($pending, $result): never {

                $completion = $this->pendingCompleter()->complete(CallerContext::forPending($pending, self::sameSiteClient()), $result);

                self::assertInstanceOf(SignInResult::class, $completion);
                self::assertTrue($completion->isSignedIn());

                throw new \RuntimeException('MFA\'s transaction failed after the hand-over.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('MFA\'s transaction failed after the hand-over.', $exception->getMessage());
        }

        self::assertSame([], $this->pendingContextFor($credential)->proofs);
        self::assertNull($this->guard()->session());
    }

    /**
     * When MFA's commit fails, its verification throws, so the sign-in result
     * never reaches a response, and the session stays pending with the guard
     * unbound, at either isolation level.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAFailedCommitNeverAnswersTheSignIn(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person     = $this->createPerson();
        $factor     = $this->confirmedFactor($person);
        $credential = $this->signInPending($person);

        $caller = CallerContext::fromRequest(self::requestCarrying($credential));

        $failing = true;

        Event::listen(TransactionCommitting::class, static function () use (&$failing): void {

            if ($failing) {
                $failing = false;

                throw new \RuntimeException('The commit failed.');
            }
        });

        try {
            Mfa::verify($caller, Submission::factor($factor->getKey(), AuthenticatorApp::code($factor)));

            self::fail('A verification whose commit failed was answered.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The commit failed.', $exception->getMessage());
        }

        self::assertFalse($failing);
        self::assertSame([], $this->pendingContextFor($credential)->proofs);
        self::assertNull($this->guard()->session());
    }

    /**
     * The completion under test, for MFA's contract kit, called as MFA calls
     * it: inside a transaction on the storage connection, outside which it
     * satisfies nothing.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\PendingCompletion
     */
    #[\Override]
    protected function pendingCompletion(): PendingCompletion
    {
        return new class ($this->pendingCompleter()) implements PendingCompletion {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\PendingCompletion  $completion
             */
            public function __construct(

                /** The completion under test. */
                private readonly PendingCompletion $completion,
            ) {}

            /**
             * Complete inside a transaction on the storage connection.
             *
             * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
             * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
             * @return ?object
             *
             * @throws \Throwable
             */
            #[\Override]
            public function complete(CallerContext $caller, VerificationResult $result): ?object
            {
                return DB::transaction(fn (): ?object => $this->completion->complete($caller, $result));
            }
        };
    }

    /**
     * A real pending session, for MFA's contract kit, on a guard whose refresh
     * token travels in a cookie once the person has signed in, so the kit's
     * completion passes the same-site check only with the caller's client.
     *
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function pendingContext(): PendingContext
    {
        if ($this->arranged !== null) {
            return $this->arranged;
        }

        $this->arranged = $this->pendingContextFor($this->signInPending($this->createPerson()));

        self::carryRefreshTokensInACookie();

        return $this->arranged;
    }

    /**
     * The pending session's caller, for MFA's contract kit, served from a
     * same-site client, which a cookie guard's same-site check passes.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \Throwable
     */
    protected function pendingCaller(): CallerContext
    {
        return CallerContext::forPending($this->pendingContext(), self::sameSiteClient());
    }

    /**
     * A verified proof of the pending session's, for MFA's contract kit.
     *
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function resultOfThePendingSession(): VerificationResult
    {
        $pending = $this->pendingContext();

        return $this->verified($pending, $this->factorProof($pending));
    }

    /**
     * A verified proof bound to another sign-in than the pending session's, for
     * MFA's contract kit.
     *
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function resultOfAnotherBinding(): VerificationResult
    {
        $pending = $this->pendingContext();

        return $this->verified($pending, $this->factorProof($pending, session: 'another-sign-in'));
    }

    /**
     * Complete the pending session with the result inside a transaction on the
     * storage connection, as MFA's verification does, for the pending session's
     * caller served from a same-site client.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function completeInTransaction(PendingContext $pending, VerificationResult $result): SignInResult
    {
        $caller = CallerContext::forPending($pending, self::sameSiteClient());

        return DB::transaction(fn (): SignInResult => $this->pendingCompleter()->complete($caller, $result));
    }

    /**
     * A client that came from a page of the API's own site: it presents the
     * site's own `Origin`, is served from that scheme and host, and carries the
     * custom header a cookie guard's same-site check requires, from another IP
     * address and user agent than the sign-in's.
     *
     * @return \SineMacula\Laravel\Mfa\Context\ClientContext
     */
    private static function sameSiteClient(): ClientContext
    {
        return new ClientContext(self::PENDING_IP, self::PENDING_AGENT, self::SITE, self::SITE, [self::CSRF_HEADER]);
    }

    /**
     * Carry the guard's refresh token in a cookie from now on, with the custom
     * header its same-site check requires.
     *
     * @return void
     */
    private static function carryRefreshTokensInACookie(): void
    {
        Config::set('auth.guards.' . self::GUARD . '.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth/refresh', 'csrf_header' => self::CSRF_HEADER]]);
    }

    /**
     * The proof again, bound as given.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private function rebound(Proof $proof, ProofBinding $binding): Proof
    {
        return new Proof($proof->kind, $proof->method, $proof->channel, $proof->reference, $proof->properties, $proof->provedAt, $binding, $proof->generation);
    }

    /**
     * A confirmed TOTP factor of the person's, on the authenticator app MFA's
     * testing helper shows codes for.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function confirmedFactor(Person $person): Factor
    {
        return Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => (string) $person->id,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
        ]);
    }

    /**
     * The factors of the further proofs the activated session holds.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return list<?string>
     *
     * @throws \Throwable
     */
    private function storedFactors(SignInResult $result): array
    {
        self::assertNotNull($result->session);

        $further = array_filter($this->proofsOf($result->session->record), static fn ($proof): bool => $proof->kind === AuthenticationProofKind::ADDITIONAL_FACTOR);

        return array_values(array_map(static fn ($proof): ?string => $proof->factor, $further));
    }

    /**
     * The guard people sign in on.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\ContextualGuard
     */
    private function guard(): ContextualGuard
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $guard = $auth->guard(self::GUARD);

        self::assertInstanceOf(ContextualGuard::class, $guard);

        return $guard;
    }

    /**
     * The position of the first statement naming the table, or `null`.
     *
     * @param  list<string>  $statements
     * @param  string  $table
     * @return ?int
     */
    private static function firstMatching(array $statements, string $table): ?int
    {
        foreach ($statements as $index => $statement) {
            if (str_contains($statement, $table)) {
                return $index;
            }
        }

        return null;
    }

    /**
     * Assert the call is refused as MFA's refusal, `not_accepted`, with the
     * detail given.
     *
     * @param  string  $detail
     * @param  \Closure(): mixed  $call
     * @return void
     */
    private static function assertRefused(string $detail, \Closure $call): void
    {
        try {
            $call();

            self::fail('The completion was not refused.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_ACCEPTED, $exception->reason);
            self::assertFalse($exception->byPackage);
            self::assertSame($detail, $exception->getMessage());
        }
    }
}
