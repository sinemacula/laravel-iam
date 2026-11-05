<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthManager as IlluminateAuthManager;
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
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\PendingSessionResolverTests;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Mfa\Pending\Concerns\ArrangesPendingSessions;
use Tests\Fixtures\Mfa\Pending\Stranger;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for MFA's pending session resolver read from
 * `laravel-authentication`'s pending sessions (IAM-3.3): MFA's contract kit,
 * the pending context a real pending session crosses as, where the credential
 * is read from, and the refusal by throwing of a credential, a guard or an
 * identity that cannot be resolved (IAM-8.2).
 *
 * The sessions are real ones, signed in with a password through
 * `laravel-authentication`, whose additional-factor policy and requirement
 * check are stand-ins that leave them pending; the other adapters are not
 * bound.
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
    use ArrangesPendingSessions, PendingSessionResolverTests, RunsAtIsolationLevels;

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
     * A pending session resolves as MFA's pending context: its identity, the
     * guard as the application, its key as the sign-in, its first factor bound
     * to that sign-in under the identity's verification generation, the
     * requirement it falls short of, MFA's actions and its expiry.
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

        $pending = $this->pendingResolver()->resolve($this->requestCarrying($credential));

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
     * The further proofs the session holds cross oldest first, bound to its
     * sign-in, without its first factor.
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
            self::assertTrue($this->sessions()->satisfy($credential, $this->authenticationProof($person, $credential, $factor))->isPending());
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

        self::assertNotNull($this->pendingResolver()->resolve($request));
    }

    /**
     * The query string never carries the credential, so a request carrying it
     * only there has no pending session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheQueryStringNeverCarriesTheCredential(): void
    {
        $credential = $this->signInPending($this->createPerson());

        self::assertNull($this->pendingResolver()->resolve(Request::create('/mfa/verify?pending_credential=' . urlencode($credential), 'POST')));
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
     * A request that may have no body is not read for a credential, whatever
     * its form body holds.
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

        self::assertNull($this->pendingResolver()->resolve($request));
    }

    /**
     * The credential is read from the field `laravel-authentication` is
     * configured to read it from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheConfiguredFieldIsRead(): void
    {
        $credential = $this->signInPending($this->createPerson());

        config()->set('authentication.session.pending_credential_field', 'sign_in_credential');

        self::assertNull($this->pendingResolver()->resolve($this->requestCarrying($credential)));
        self::assertNotNull($this->pendingResolver()->resolve(Request::create('/mfa/verify', 'POST', ['sign_in_credential' => $credential])));
    }

    /**
     * The credential is read for the pending completion as it is for a
     * resolution.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCredentialIsReadForTheCompletion(): void
    {
        $credential = $this->signInPending($this->createPerson());

        self::assertSame($credential, $this->pendingResolver()->credential($this->requestCarrying($credential), self::GUARD));
        self::assertNull($this->pendingResolver()->credential(Request::create('/mfa/verify', 'POST'), self::GUARD));
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
        $this->expectExceptionMessage('authentication.session.pending_credential_field must name the body field a pending credential is read from.');

        $this->pendingResolver()->resolve($this->requestCarrying('anything'));
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
     * A value in the field that is not a credential at all is refused as one
     * naming no pending session.
     *
     * @param  mixed  $credential
     * @return void
     */
    #[DataProvider('provideValuesThatAreNoCredential')]
    public function testAValueThatIsNoCredentialIsRefused(mixed $credential): void
    {
        self::assertUnresolvedCredential(fn (): mixed => $this->pendingResolver()->resolve(Request::create('/mfa/verify', 'POST', ['pending_credential' => $credential])));
    }

    /**
     * The credential of a session that has activated names no pending session
     * any more, and is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCredentialOfAnActivatedSessionIsRefused(): void
    {
        $person     = $this->createPerson();
        $credential = $this->signInPending($person);

        self::assertTrue($this->sessions()->satisfy($credential, $this->authenticationProof($person, $credential, 'factor-1'))->isSignedIn());

        self::assertUnresolvedCredential(fn (): mixed => $this->pendingResolver()->resolve($this->requestCarrying($credential)));
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
     * A credential on a default guard that holds no sessions, or names no
     * guard, is refused; a request carrying none still has no pending session.
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

        self::assertNull($this->pendingResolver()->resolve(Request::create('/mfa/verify', 'POST')));
        self::assertUnresolvedGuard($guard, fn (): mixed => $this->pendingResolver()->resolve($this->requestCarrying($credential)));
    }

    /**
     * An auth manager that is not `laravel-authentication`'s holds no session
     * service, so a credential is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAuthManagerThatIsNotLaravelAuthenticationsIsRefused(): void
    {
        $credential = $this->signInPending($this->createPerson());

        $this->app?->instance('auth', new IlluminateAuthManager($this->app));

        self::assertUnresolvedGuard(self::GUARD, fn (): mixed => $this->pendingResolver()->resolve($this->requestCarrying($credential)));
    }

    /**
     * A pending session of an identity that holds no factors names no one MFA
     * could verify a factor for, and is refused.
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
        $result = $this->sessions(self::STRANGERS)->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD]);

        self::assertTrue($result->isPending());
        self::assertNotNull($result->credential);

        config()->set('auth.defaults.guard', self::STRANGERS);

        try {
            $this->pendingResolver()->resolve($this->requestCarrying($result->credential->reveal()));

            self::fail('A pending session of an identity without factors was resolved.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
            self::assertStringContainsString(sprintf('[%s]', Stranger::class), $exception->getMessage());
            self::assertStringContainsString('MultiFactorAuthenticatable', $exception->getMessage());
        }
    }

    /**
     * Resolving a pending session takes no lock and writes nothing, at either
     * isolation level, so it never orders itself before MFA's locks.
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
        $request    = $this->requestCarrying($credential);
        $connection = DB::connection();

        $connection->flushQueryLog();
        $connection->enableQueryLog();

        $connection->transaction(fn (): mixed => $this->pendingResolver()->resolve($request));

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
     * A request carrying a pending credential that names no pending session,
     * for MFA's contract kit.
     *
     * @return \Illuminate\Http\Request
     */
    #[\Override]
    protected function requestWithInvalidPendingCredential(): Request
    {
        return Request::create('/mfa/verify', 'POST', ['pending_credential' => 'not-a-pending-credential']);
    }

    /**
     * `laravel-authentication`'s proof of a further factor verified now for the
     * person's pending session the credential names.
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
