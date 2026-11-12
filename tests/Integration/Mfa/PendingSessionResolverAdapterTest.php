<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Proofs\Channel as AuthenticationChannel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind as AuthenticationProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation as AuthenticationEvaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties as AuthenticationProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding as AuthenticationBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\PendingSessionResolverTests;
use Tests\Concerns\BindsStrayRequests;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Mfa\Pending\Concerns\ArrangesPendingSessions;
use Tests\Fixtures\Mfa\Pending\Stranger;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Tests for MFA's pending session resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSessionResolverAdapter::class)]
#[WithConfig(MfaSeams::SWITCH, false, defer: false)]
final class PendingSessionResolverAdapterTest extends TestCase
{
    use ArrangesPendingSessions, BindsStrayRequests, PendingSessionResolverTests, RunsAtIsolationLevels;

    /** @var string The guard strangers, who hold no factors, sign in on. */
    private const string STRANGERS = 'strangers';

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
     * A pending session resolves as MFA's pending context.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionResolvesAsItsPendingContext(): void
    {
        $person     = $this->createPerson();
        $credential = $this->signInPending($person);
        $session    = $this->sessions()->pending($credential);

        self::assertNotNull($session);

        $pending = $this->pendingResolver()->fromRequest(self::requestCarrying($credential));

        self::assertNotNull($pending);
        self::assertSame($person->getKey(), $pending->identity->getAuthIdentifier());
        self::assertSame(self::GUARD, $pending->application);
        self::assertSame($this->signInReference($session->session), $pending->sessionId);
        self::assertSame(Requirement::none()->withAdditionalVerification()->toArray(), $pending->requirement->toArray());
        self::assertSame([
            PendingAction::LIST_FACTORS,
            PendingAction::SEND_CODE,
            PendingAction::VERIFY,
            PendingAction::START_BOOTSTRAP_ENROLLMENT,
            PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT,
        ], $pending->actions);
        self::assertTrue($session->expiresAt->equalTo($pending->expiresAt));
        self::assertSame([], $pending->proofs);

        $first = $pending->firstFactor;

        self::assertSame(ProofKind::FIRST_FACTOR, $first->kind);
        self::assertSame('password', $first->method);
        self::assertSame(ChannelKind::PASSWORD, $first->channel?->kind);
        self::assertSame(
            [$person->getMorphClass(), (string) $person->id, self::GUARD, $pending->sessionId, Purpose::SIGN_IN],
            [$first->binding->identityType, $first->binding->identityKey, $first->binding->application, $first->binding->sessionId, $first->binding->purpose],
        );
        self::assertSame(VerificationGeneration::current($person), $first->generation);
    }

    /**
     * Further proofs cross oldest first, without the first factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFurtherProofsCrossOldestFirstWithoutTheFirstFactor(): void
    {
        $this->bindPendingSeams(3);

        $person     = $this->createPerson();
        $credential = $this->signInPending($person);

        foreach (['factor-1', 'factor-2'] as $factor) {
            self::assertTrue($this->sessions()->satisfy($credential, $this->authenticationProof($person, $credential, $factor), self::client())->isPending());
        }

        $pending = $this->pendingContextFor($credential);

        self::assertSame(['factor-1', 'factor-2'], array_map(static fn ($proof): ?string => $proof->reference, $pending->proofs));

        foreach ($pending->proofs as $proof) {
            self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proof->kind);
            self::assertSame($pending->sessionId, $proof->binding->sessionId);
            self::assertSame($pending->firstFactor->generation, $proof->generation);
        }
    }

    /**
     * A JSON body carries the credential as a form body does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJsonBodyCarriesTheCredential(): void
    {
        $credential = $this->signInPending($this->createPerson());

        $request = Request::create('/mfa/verify', 'POST', server: ['CONTENT_TYPE' => 'application/json'], content: (string) json_encode(['pending_credential' => $credential]));

        self::assertNotNull($this->pendingResolver()->fromRequest($request));
    }

    /**
     * The query string never carries the credential.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheQueryStringNeverCarriesTheCredential(): void
    {
        $credential = $this->signInPending($this->createPerson());

        self::assertNull($this->pendingResolver()->fromRequest(Request::create('/mfa/verify?pending_credential=' . urlencode($credential), 'POST')));
    }

    /**
     * Rows of `[method]` for the requests that may have no body.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMethodsWithoutABody(): iterable
    {
        yield 'get' => ['GET'];

        yield 'head' => ['HEAD'];
    }

    /**
     * A request that may have no body is not read for a credential.
     *
     * @param  string  $method
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMethodsWithoutABody')]
    public function testARequestThatMayHaveNoBodyIsNotRead(string $method): void
    {
        $credential = $this->signInPending($this->createPerson());

        $request = new Request(request: ['pending_credential' => $credential], server: ['REQUEST_METHOD' => $method]);

        self::assertNull($this->pendingResolver()->fromRequest($request));
    }

    /**
     * The credential is read from the configured field.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheConfiguredFieldIsRead(): void
    {
        $credential = $this->signInPending($this->createPerson());

        config()->set('authentication.session.pending_credential_field', 'sign_in_credential');

        self::assertNull($this->pendingResolver()->fromRequest(self::requestCarrying($credential)));
        self::assertNotNull($this->pendingResolver()->fromRequest(Request::create('/mfa/verify', 'POST', ['sign_in_credential' => $credential])));
    }

    /**
     * The pending context keeps the credential it was read from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheContextKeepsItsCredential(): void
    {
        $credential = $this->signInPending($this->createPerson());

        self::assertSame($credential, $this->pendingContextFor($credential)->credential());
    }

    /**
     * Revalidating reads the pending session again as it stands now.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevalidatingReadsTheSessionAsItStandsNow(): void
    {
        $this->bindPendingSeams(3);

        $person     = $this->createPerson();
        $credential = $this->signInPending($person);
        $pending    = $this->pendingContextFor($credential);

        self::assertTrue($this->sessions()->satisfy($credential, $this->authenticationProof($person, $credential, 'factor-1'), self::client())->isPending());

        $now = $this->pendingResolver()->revalidate($pending);

        self::assertNotNull($now);
        self::assertNotSame($pending, $now);
        self::assertSame([], $pending->proofs);
        self::assertSame(['factor-1'], array_map(static fn ($proof): ?string => $proof->reference, $now->proofs));
        self::assertSame($pending->sessionId, $now->sessionId);
        self::assertSame(self::GUARD, $now->application);
        self::assertSame($credential, $now->credential());
    }

    /**
     * Revalidating reads the context's application's guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevalidatingReadsTheContextsApplication(): void
    {
        $credential = $this->signInPending($this->createPerson());
        $pending    = $this->pendingContextFor($credential);

        config()->set('auth.defaults.guard', 'web');

        self::assertSame($pending->sessionId, $this->pendingResolver()->revalidate($pending)?->sessionId);
    }

    /**
     * A context that kept no credential no longer stands.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAContextWithoutACredentialNoLongerStands(): void
    {
        $pending = self::keeping($this->pendingContextFor($this->signInPending($this->createPerson())), null);

        self::assertNull($this->pendingResolver()->revalidate($pending));
    }

    /**
     * A session activated or discarded since it was served no longer stands.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatEndedNoLongerStands(): void
    {
        $person    = $this->createPerson();
        $activated = $this->signInPending($person);
        $discarded = $this->signInPending($person);
        $first     = $this->pendingContextFor($activated);
        $second    = $this->pendingContextFor($discarded);

        self::assertTrue($this->sessions()->satisfy($activated, $this->authenticationProof($person, $activated, 'factor-1'), self::client())->isSignedIn());

        $this->sessions()->discard($discarded, self::client());

        self::assertNull($this->pendingResolver()->revalidate($first));
        self::assertNull($this->pendingResolver()->revalidate($second));
    }

    /**
     * A credential naming another pending session no longer stands.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherSessionNoLongerStands(): void
    {
        $person  = $this->createPerson();
        $other   = $this->signInPending($person);
        $pending = $this->pendingContextFor($this->signInPending($person));

        self::assertNull($this->pendingResolver()->revalidate(self::keeping($pending, $other)));

        $stranger = $this->createPerson();
        $owner    = ProofOwner::of($stranger);
        $own      = $this->pendingContextFor($other);
        $first    = $own->firstFactor;
        $binding  = new ProofBinding($owner->type, $owner->key, $own->application, $own->sessionId, Purpose::SIGN_IN);
        $theirs   = new PendingContext(
            $stranger,
            $own->application,
            $own->sessionId,
            new Proof($first->kind, $first->method, $first->channel, $first->reference, $first->properties, $first->provedAt, $binding, $first->generation),
            $own->requirement,
            $own->actions,
            $own->expiresAt,
            credential: $other,
        );

        self::assertNotNull($this->pendingResolver()->revalidate($own));
        self::assertNull($this->pendingResolver()->revalidate($theirs));
    }

    /**
     * Only the request handed in is read, never one bound in the container.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheRequestHandedInIsRead(): void
    {
        $person     = $this->createPerson();
        $credential = $this->signInPending($person);
        $own        = $this->sessions()->pending($credential);

        $this->bindStrayRequest([self::CREDENTIAL_FIELD => $this->signInPending($person)]);

        self::assertNotNull($own);
        self::assertSame($this->signInReference($own->session), $this->pendingResolver()->fromRequest(self::requestCarrying($credential))?->sessionId);
        self::assertNull($this->pendingResolver()->fromRequest(Request::create(self::VERIFY_PATH, 'POST')));
    }

    /**
     * Revalidating reads no request bound in the container.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevalidatingReadsNoBoundRequest(): void
    {
        $person     = $this->createPerson();
        $credential = $this->signInPending($person);
        $pending    = $this->pendingContextFor($credential);

        $this->bindStrayRequest([self::CREDENTIAL_FIELD => $this->signInPending($person)]);

        $now = $this->pendingResolver()->revalidate($pending);

        self::assertSame($pending->sessionId, $now?->sessionId);
        self::assertSame($credential, $now->credential());

        $this->bindStrayRequest([self::CREDENTIAL_FIELD => $credential]);

        self::assertNull($this->pendingResolver()->revalidate(self::keeping($pending, null)));
    }

    /**
     * A credential handed in is read on the application's guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialHandedInIsReadOnTheApplicationsGuard(): void
    {
        $person     = $this->createPerson();
        $credential = $this->signInPending($person);
        $expected   = $this->pendingContextFor($credential);

        $this->bindStrayRequest([self::CREDENTIAL_FIELD => $this->signInPending($person)]);

        config()->set('auth.defaults.guard', 'web');

        $pending = $this->pendingResolver()->fromCredential(self::GUARD, $credential);

        self::assertNotNull($pending);
        self::assertSame($expected->sessionId, $pending->sessionId);
        self::assertSame(self::GUARD, $pending->application);
        self::assertEquals(ProofOwner::of($person), ProofOwner::of($pending->identity));
        self::assertSame($credential, $pending->credential());
    }

    /**
     * A credential handed in that names no live pending session is none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialHandedInThatNamesNoSessionIsNone(): void
    {
        $this->bindStrayRequest([self::CREDENTIAL_FIELD => $this->signInPending($this->createPerson())]);

        self::assertNull($this->pendingResolver()->fromCredential(self::GUARD, 'not-a-pending-credential'));
    }

    /**
     * Rows of `[field]` that name no body field.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideFieldsThatAreNoField(): iterable
    {
        yield 'none' => [null];

        yield 'empty' => [''];

        yield 'a list' => [['pending_credential']];
    }

    /**
     * A configuration naming no field fails closed.
     *
     * @param  mixed  $field
     * @return void
     */
    #[DataProvider('provideFieldsThatAreNoField')]
    public function testAConfigurationNamingNoFieldFailsClosed(mixed $field): void
    {
        config()->set('authentication.session.pending_credential_field', $field);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.session.pending_credential_field must be a field name without `.`, spaces or brackets.');

        $this->pendingResolver()->fromRequest(self::requestCarrying('anything'));
    }

    /**
     * Rows of `[value]` that are no credential.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideValuesThatAreNoCredential(): iterable
    {
        yield 'empty' => [''];

        yield 'a list' => [['credential']];

        yield 'no session' => ['01JC0000000000000000000000.not-the-secret'];
    }

    /**
     * A field value that is not a credential is refused.
     *
     * @param  mixed  $credential
     * @return void
     */
    #[DataProvider('provideValuesThatAreNoCredential')]
    public function testAValueThatIsNoCredentialIsRefused(mixed $credential): void
    {
        self::assertUnresolvedCredential(fn (): mixed => $this->pendingResolver()->fromRequest(Request::create('/mfa/verify', 'POST', ['pending_credential' => $credential])));
    }

    /**
     * The credential of an activated session is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCredentialOfAnActivatedSessionIsRefused(): void
    {
        $person     = $this->createPerson();
        $credential = $this->signInPending($person);

        self::assertTrue($this->sessions()->satisfy($credential, $this->authenticationProof($person, $credential, 'factor-1'), self::client())->isSignedIn());

        self::assertUnresolvedCredential(fn (): mixed => $this->pendingResolver()->fromRequest(self::requestCarrying($credential)));
    }

    /**
     * Rows of `[guard]` that hold no sessions.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideGuardsThatHoldNoSessions(): iterable
    {
        yield 'a session guard' => ['web'];

        yield 'no guard' => ['nowhere'];
    }

    /**
     * A default guard that holds no sessions, or names none, is refused.
     *
     * @param  string  $guard
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideGuardsThatHoldNoSessions')]
    public function testADefaultGuardThatHoldsNoSessionsIsRefused(string $guard): void
    {
        $credential = $this->signInPending($this->createPerson());

        config()->set('auth.defaults.guard', $guard);

        self::assertNull($this->pendingResolver()->fromRequest(Request::create('/mfa/verify', 'POST')));
        self::assertUnresolvedGuard($guard, fn (): mixed => $this->pendingResolver()->fromRequest(self::requestCarrying($credential)));
    }

    /**
     * A pending session of an identity that holds no factors is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionOfAnIdentityWithoutFactorsIsRefused(): void
    {
        config()->set('auth.guards.' . self::STRANGERS, ['driver' => 'jwt', 'provider' => self::STRANGERS, 'application' => ['methods' => ['password']]]);
        config()->set('auth.providers.' . self::STRANGERS, ['driver' => 'model', 'model' => Stranger::class]);

        $person = $this->createPerson();
        $result = $this->sessions(self::STRANGERS)->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], new SignInContext(self::client()));

        self::assertTrue($result->isPending());
        self::assertNotNull($result->credential);

        config()->set('auth.defaults.guard', self::STRANGERS);

        try {
            $this->pendingResolver()->fromRequest(self::requestCarrying($result->credential->reveal()));

            self::fail('A pending session of an identity without factors was resolved.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
            self::assertStringContainsString(sprintf('[%s]', Stranger::class), $exception->getMessage());
            self::assertStringContainsString('MultiFactorAuthenticatable', $exception->getMessage());
        }
    }

    /**
     * Resolving a pending session takes no lock and writes nothing.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testResolvingTakesNoLockAndWritesNothing(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $credential = $this->signInPending($this->createPerson());
        $request    = self::requestCarrying($credential);
        $connection = DB::connection();

        $connection->flushQueryLog();
        $connection->enableQueryLog();

        $connection->transaction(fn (): mixed => $this->pendingResolver()->fromRequest($request));

        $statements = array_map(static fn (array $query): string => strtolower($query['query']), $connection->getQueryLog());

        self::assertNotSame([], $statements);

        foreach ($statements as $statement) {
            self::assertDoesNotMatchRegularExpression('/\bfor (update|share)\b|lock in share mode|^\s*(insert|update|delete)\b/', $statement);
        }
    }

    /**
     * The resolver under test, for MFA's contract kit.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver
     */
    #[\Override]
    protected function pendingSessionResolver(): PendingSessionResolver
    {
        return $this->pendingResolver();
    }

    /**
     * A request carrying no pending credential, for MFA's contract kit.
     *
     * @return \Illuminate\Http\Request
     */
    #[\Override]
    protected function requestWithoutPendingCredential(): Request
    {
        return Request::create('/mfa/verify', 'POST', ['code' => '123456']);
    }

    /**
     * A request carrying a pending credential that names no pending session.
     *
     * @return \Illuminate\Http\Request
     */
    #[\Override]
    protected function requestWithInvalidPendingCredential(): Request
    {
        return Request::create('/mfa/verify', 'POST', ['pending_credential' => 'not-a-pending-credential']);
    }

    /**
     * The proof of a further factor verified now for the pending session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $credential
     * @param  string  $factor
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofResult
     *
     * @throws \Throwable
     */
    private function authenticationProof(Person $person, string $credential, string $factor): ProofResult
    {
        $pending = $this->sessions()->pending($credential);

        self::assertNotNull($pending);

        return new ProofResult(
            AuthenticationProofKind::ADDITIONAL_FACTOR,
            'totp',
            new AuthenticationChannel(AuthenticationChannelKind::AUTHENTICATOR_APP, $factor),
            $factor,
            new AuthenticationProperties,
            new AuthenticationEvaluation(true, true),
            ['otp'],
            CarbonImmutable::now(),
            new AuthenticationBinding($person, self::GUARD, $pending->id, AuthenticationPurpose::SIGN_IN),
        );
    }

    /**
     * Assert the resolution refuses with no pending session of the guard.
     *
     * @param  \Closure(): mixed  $resolve
     * @return void
     */
    private static function assertUnresolvedCredential(\Closure $resolve): void
    {
        try {
            $resolve();

            self::fail('A credential naming no pending session was answered.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::SESSION, $exception->kind);
            self::assertSame(self::GUARD, $exception->application);
            self::assertSame(
                'The request\'s pending credential names no live pending session of the guard [api] that may still activate,'
                . ' so the request is refused rather than served as anyone.',
                $exception->getMessage(),
            );
        }
    }

    /**
     * Assert the resolution refuses a guard that holds no sessions.
     *
     * @param  string  $guard
     * @param  \Closure(): mixed  $resolve
     * @return void
     */
    private static function assertUnresolvedGuard(string $guard, \Closure $resolve): void
    {
        try {
            $resolve();

            self::fail(sprintf('A pending session was resolved on [%s].', $guard));
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::GUARD, $exception->kind);
            self::assertSame($guard, $exception->application);
            self::assertStringStartsWith(sprintf('The application [%s] is not a laravel-authentication guard', $guard), $exception->getMessage());
        }
    }
}
