<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationStatus;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Authentication\Sessions\FactorRemoval;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\PasskeyFactorGateAdapter;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\ContextEvent;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Events\PasskeyAssociated;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociationResult;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\PasskeyChangeGateTests;
use Tests\Concerns\BindsStrayRequests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RegistersPasskeys;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for the passkey factor gate over MFA's passkey change gate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyFactorGateAdapter::class)]
final class PasskeyFactorGateAdapterTest extends TestCase
{
    use ArrangesFactorChanges, BindsStrayRequests, MigratesMembers, PasskeyChangeGateTests, RegistersPasskeys, RunsAtIsolationLevels, SignsInPeople {
        RegistersPasskeys::registerPasskey as registerThroughAuthentication;
    }

    /** @var string A credential id, in unpadded base64url. */
    private const string CREDENTIAL = 'cGFzc2tleS1mYWN0b3ItZ2F0ZQ';

    /** @var string The IP address of the client a registration is handed, unlike the tests'. */
    private const string HANDED_IP = '203.0.113.24';

    /** @var string The user agent of the client a registration is handed, unlike the tests'. */
    private const string HANDED_AGENT = 'handed-client';

    /** @var (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null The session the gated identity acts on. */
    private (EloquentSession&Model)|null $gatedSession = null;

    /**
     * An enrolment's passkey becomes a factor and the session is judged again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEnrolmentRegistrationBecomesAFactor(): void
    {
        [$person, $session] = $this->freshPerson();

        $registration = $this->registerForEnrolment($person, $session);
        $factor       = Factor::query()->sole();

        self::assertTrue($registration->isRegistered());
        self::assertNotNull($registration->factor);
        self::assertSame($factor->id, $registration->factor->factor);
        self::assertSame('passkey', $factor->getType());
        self::assertSame(self::CREDENTIAL, $factor->getCredentialReference());
        self::assertSame('Laptop', $factor->getLabel());
        self::assertSame(FactorStatus::CONFIRMED, $factor->getStatus());
        self::assertSame(self::GUARD, $factor->getApplication());

        $completion = $registration->factor->completion;

        self::assertInstanceOf(PasskeyAssociationResult::class, $completion);
        self::assertSame($factor->id, $completion->factor->id);
        self::assertNull($completion->verification);
        self::assertInstanceOf(FactorChangeResult::class, $completion->completion());
        self::assertTrue($completion->completion()->isPending());
        self::assertTrue(PasskeyAssociation::query()->where('factor_id', $factor->id)->exists());
    }

    /**
     * A registration without a binding stays a sign-in passkey.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationWithoutABindingStaysASignInPasskey(): void
    {
        [$person] = $this->freshPerson();

        $registration = $this->registerThroughAuthentication($person, self::CREDENTIAL);

        self::assertTrue($registration->isRegistered());
        self::assertNull($registration->factor);
        self::assertSame(0, Factor::query()->count());
        self::assertTrue($this->isPasskeyStored($person, self::CREDENTIAL));
    }

    /**
     * A registration bound for anything but an enrolment keeps nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationBoundForAnotherPurposeIsRefused(): void
    {
        [$person, $session] = $this->freshPerson();

        $refusal = self::refusal(fn (): mixed => $this->registerThroughAuthentication($person, self::CREDENTIAL, $this->bindingOf($person, $session, Purpose::STEP_UP)));

        self::assertSame(FailureReason::NOT_FOUND, $refusal->reason);
        self::assertFalse($this->isPasskeyStored($person, self::CREDENTIAL));
        self::assertSame(0, Factor::query()->count());
    }

    /**
     * A bootstrap enrolment's passkey activates the pending session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInsBootstrapEnrolmentActivatesTheSession(): void
    {
        [$person, $session, $credential] = $this->pendingSignIn();

        $registration = $this->registerThroughAuthentication($person, self::CREDENTIAL, $this->bindingOf($person, $session, Purpose::ENROLLMENT), pending: $credential);
        $factor       = Factor::query()->sole();

        self::assertTrue($registration->isRegistered());
        self::assertSame(FactorStatus::CONFIRMED, $factor->getStatus());
        self::assertSame(self::CREDENTIAL, $factor->getCredentialReference());

        $completion = $registration->factor->completion ?? null;

        self::assertInstanceOf(PasskeyAssociationResult::class, $completion);
        self::assertSame($factor->id, $completion->factor->id);

        $verification = $completion->verification ?? self::fail('The registration answered no verification of the pending session.');

        self::assertTrue($verification->isVerified());

        $signIn = $verification->completion();

        self::assertInstanceOf(SignInResult::class, $signIn);
        self::assertTrue($signIn->isSignedIn());
        self::assertSame(SessionStatus::ACTIVE, Session::query()->whereKey($session->getKey())->sole()->getStatus());
        self::assertTrue(PasskeyAssociation::query()->where('factor_id', $factor->id)->exists());
    }

    /**
     * A bad pending credential is answered `pending_invalid`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABadPendingCredentialIsAnsweredAsPendingInvalid(): void
    {
        [$person, $session] = $this->pendingSignIn();

        $binding      = $this->bindingOf($person, $session, Purpose::ENROLLMENT);
        $registration = $this->registerThroughAuthentication($person, self::CREDENTIAL, $binding, pending: 'not-a-pending-credential');

        self::assertSame(PasskeyRegistrationStatus::PENDING_INVALID, $registration->status);
        self::assertFalse($this->isPasskeyStored($person, self::CREDENTIAL));
        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, PasskeyAssociation::query()->count());
        self::assertSame(SessionStatus::PENDING, Session::query()->whereKey($session->getKey())->sole()->getStatus());
    }

    /**
     * A bootstrap enrolment is served to the client handed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABootstrapEnrolmentIsServedToTheClientHandedIn(): void
    {
        [, , $stray]                     = $this->pendingSignIn();
        [$person, $session, $credential] = $this->pendingSignIn();

        $client   = new ClientContext(self::HANDED_IP, self::HANDED_AGENT);
        $contexts = [];

        Event::listen(PasskeyAssociated::class, static function (ContextEvent $event) use (&$contexts): void {
            $contexts[] = $event->context;
        });

        $this->bindStrayRequest(['pending_credential' => $stray]);

        $binding      = $this->bindingOf($person, $session, Purpose::ENROLLMENT);
        $registration = $this->registerThroughAuthentication($person, self::CREDENTIAL, $binding, client: $client, pending: $credential);

        self::assertTrue($registration->isRegistered());

        $record = Session::query()->whereKey($session->getKey())->sole();

        self::assertSame(SessionStatus::ACTIVE, $record->getStatus());
        self::assertSame([self::HANDED_IP, self::HANDED_AGENT], [$record->getAttribute('last_used_ip'), $record->getAttribute('last_used_user_agent')]);
        self::assertNotNull($this->sessions()->pending($stray));
        self::assertCount(1, $contexts);
        self::assertSame([self::HANDED_IP, self::HANDED_AGENT], [$contexts[0]['ip'], $contexts[0]['user_agent']]);
    }

    /**
     * Rows of `[whose]` for a pending credential of no sign-in of the identity.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideForeignPendingCredentials(): iterable
    {
        yield 'none' => ['none'];

        yield 'another identity\'s' => ['another'];
    }

    /**
     * A pending credential of no sign-in of the identity is `not_found`.
     *
     * @param  string  $whose
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideForeignPendingCredentials')]
    public function testAPendingCredentialOfNoSignInOfTheIdentitysIsRefused(string $whose): void
    {
        [$other, , $foreign] = $this->pendingSignIn();
        [$person, $session]  = $this->pendingSignIn();

        self::assertNotSame($other->getKey(), $person->getKey());

        $credential = new Secret($whose === 'none' ? 'not-a-pending-credential' : $foreign);
        $binding    = $this->bindingOf($person, $session, Purpose::ENROLLMENT);

        $register = fn (): mixed => $this->gate()->registering($person, self::GUARD, self::registeredPasskey(), $binding, 'Laptop', self::client(), $credential);
        $refusal  = self::refusal(static fn (): mixed => self::storage()->transaction($register));

        self::assertSame(FailureReason::NOT_FOUND, $refusal->reason);
        self::assertSame('The pending credential names no pending sign-in of the identity on the application.', $refusal->getMessage());
        self::assertSame(0, Factor::query()->count());
    }

    /**
     * A registration MFA refuses keeps neither the passkey nor any factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationMfaRefusesKeepsNothing(): void
    {
        $this->travel(-1)->hours();

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->travelBack();

        $refusal = self::refusal(fn (): mixed => $this->registerForEnrolment($person, $session));

        self::assertSame(FailureReason::NOT_FRESH, $refusal->reason);
        self::assertFalse($this->isPasskeyStored($person, self::CREDENTIAL));
        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, PasskeyAssociation::query()->count());
    }

    /**
     * Removing a passkey removes its factor and association in one change.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testRemovingAPasskeyNeverLeavesItsFactorStanding(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, $session, $factor, $kept] = $this->passkeyFactorBesideAnother();

        $this->stepUpWith($person, $session, $kept->id);

        $removal = $this->passkeys()->remove($person, $this->passkeyId(), self::client());

        self::assertTrue($removal->isRemoved());
        self::assertInstanceOf(FactorRemoval::class, $removal->completion);
        self::assertFalse($this->isPasskeyStored($person, self::CREDENTIAL));
        self::assertNull(Factor::query()->find($factor->id));
        self::assertNotNull(Factor::query()->find($kept->id));
        self::assertSame(0, PasskeyAssociation::query()->count());
        self::assertSame(0, self::storage()->transactionLevel());
    }

    /**
     * A removal MFA refuses keeps the passkey, its factor and its association.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARemovalMfaRefusesKeepsThePasskeyAndItsFactor(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, , $factor] = $this->passkeyFactorBesideAnother();

        $refusal = self::refusal(fn (): mixed => $this->passkeys()->remove($person, $this->passkeyId(), self::client()));

        self::assertSame(FailureReason::NOT_FRESH, $refusal->reason);
        self::assertTrue($this->isPasskeyStored($person, self::CREDENTIAL));
        self::assertNotNull(Factor::query()->find($factor->id));
        self::assertSame(1, PasskeyAssociation::query()->count());
        self::assertSame(0, self::storage()->transactionLevel());
    }

    /**
     * Removing a sign-in passkey removes the passkey alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingASignInPasskeyAnswersNoCompletion(): void
    {
        [$person] = $this->freshPerson();

        $this->registerThroughAuthentication($person, self::CREDENTIAL);

        $removal = $this->passkeys()->remove($person, $this->passkeyId(), self::client());

        self::assertTrue($removal->isRemoved());
        self::assertNull($removal->completion);
        self::assertFalse($this->isPasskeyStored($person, self::CREDENTIAL));
    }

    /**
     * MFA's locks and the session row are taken before the passkey's row.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testMfasLocksComeBeforeThePasskeysRow(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, $session] = $this->freshPerson();

        $this->requireNothing();

        DB::enableQueryLog();

        $this->registerForEnrolment($person, $session);

        self::assertLocksPrecede('insert (ignore )?into');

        $kept = $this->confirmedFactor($person);

        $this->stepUpWith($person, $session, $kept->id);

        DB::flushQueryLog();

        self::assertTrue($this->passkeys()->remove($person, $this->passkeyId(), self::client())->isRemoved());
        self::assertLocksPrecede('delete from');
    }

    /**
     * A request bound in the container never stands in for the caller.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundRequestNeverReachesTheChange(): void
    {
        $stranger = $this->createPerson();

        $this->confirmedFactor($stranger);

        $pending = $this->attemptSignIn($stranger);

        self::assertTrue($pending->isPending(), (string) $pending->reason?->value);
        self::assertNotNull($pending->credential);

        [$person, $session] = $this->freshPerson();

        $this->requireNothing();

        $contexts = [];

        Event::listen([PasskeyAssociated::class, FactorRemoved::class], static function (ContextEvent $event) use (&$contexts): void {
            $contexts[] = $event->context;
        });

        $this->bindStrayRequest(['pending_credential' => $pending->credential->reveal()]);

        self::assertTrue($this->registerForEnrolment($person, $session)->isRegistered());

        $key    = EventContext::scalarKey($person->getKey());
        $factor = Factor::query()->where('authenticatable_id', $key)->sole();

        self::assertSame(self::GUARD, $factor->getApplication());

        $this->stepUpWith($person, $session, $this->confirmedFactor($person)->id);

        self::assertTrue($this->passkeys()->remove($person, $this->passkeyId(), self::client())->isRemoved());
        self::assertNull(Factor::query()->find($factor->id));
        self::assertCount(2, $contexts);

        foreach ($contexts as $context) {
            self::assertSame($key, $context['identity_id']);
            self::assertSame(self::GUARD, $context['application']);
            self::assertSame([$session->getKey(), self::CLIENT_IP, self::CLIENT_AGENT], [$context['session_id'], $context['ip'], $context['user_agent']]);
        }
    }

    /**
     * An identity MFA holds no factors for has nothing associated or removed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityMfaHoldsNoFactorsForIsLeftAlone(): void
    {
        $stranger = new class extends User implements Identity {};
        $binding  = new ProofBinding($stranger, self::GUARD, 'sign-in', Purpose::ENROLLMENT);

        self::assertNull($this->gate()->registering($stranger, self::GUARD, self::registeredPasskey(), $binding, 'Laptop', self::client(), null));
        self::assertNull($this->gate()->removing($stranger, self::GUARD, 'passkey', self::CREDENTIAL, self::client()));
    }

    /**
     * An application without passkeys associates nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationWithoutPasskeysAssociatesNothing(): void
    {
        [$person, $session] = $this->freshPerson();

        $binding     = $this->bindingOf($person, $session, Purpose::ENROLLMENT);
        $register    = fn (): mixed => $this->gate()->registering($person, 'other', self::registeredPasskey(), $binding, 'Laptop', self::client(), null);
        $association = self::storage()->transaction($register);

        self::assertNull($association);
        self::assertSame(0, Factor::query()->count());
    }

    /**
     * A binding whose session is no non-empty string or integer throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABindingWithoutASessionIsUnresolved(): void
    {
        [$person] = $this->freshPerson();

        $binding = new ProofBinding($person, self::GUARD, null, Purpose::ENROLLMENT);

        try {
            self::storage()->transaction(fn (): mixed => $this->gate()->registering($person, self::GUARD, self::registeredPasskey(), $binding, 'Laptop', self::client(), null));
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::SESSION, $exception->kind);
            self::assertSame(self::GUARD, $exception->application);
            self::assertSame(0, Factor::query()->count());

            return;
        }

        self::fail('A binding without a session was resolved.');
    }

    /**
     * The identity registering passkeys, on an application offering them.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function gatedIdentity(): MultiFactorAuthenticatable
    {
        [$person, $session] = $this->freshPerson();

        $this->gatedSession = $session;

        return $person;
    }

    /**
     * The application it registers them on.
     *
     * @return string
     */
    #[\Override]
    protected function gatedApplication(): string
    {
        return self::GUARD;
    }

    /**
     * Register a passkey bound for an MFA enrolment.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $credentialId
     * @return mixed
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function registerPasskey(MultiFactorAuthenticatable $identity, #[\SensitiveParameter] string $credentialId): mixed
    {
        self::assertInstanceOf(Person::class, $identity);
        self::assertNotNull($this->gatedSession);

        return $this->registerThroughAuthentication($identity, $credentialId, $this->bindingOf($identity, $this->gatedSession, Purpose::ENROLLMENT));
    }

    /**
     * Ask the gate to let a passkey be registered for an MFA enrolment.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @return mixed
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function gateRegistering(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId): mixed
    {
        self::assertInstanceOf(Person::class, $identity);
        self::assertNotNull($this->gatedSession);

        $binding = $this->bindingOf($identity, $this->gatedSession, Purpose::ENROLLMENT);

        return $this->gate()->registering($identity, $application, self::registeredPasskey($credentialId), $binding, 'Laptop', self::client(), null);
    }

    /**
     * Ask the gate to let a passkey be removed.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @return mixed
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function gateRemoving(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId): mixed
    {
        self::assertInstanceOf(Person::class, $identity);

        return $this->gate()->removing($identity, $application, 'passkey', $credentialId, self::client());
    }

    /**
     * Whether `laravel-authentication` kept the credential.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $credentialId
     * @return bool
     */
    #[\Override]
    protected function isPasskeyStored(MultiFactorAuthenticatable $identity, #[\SensitiveParameter] string $credentialId): bool
    {
        return Passkey::query()->where('credential_id', $credentialId)->exists();
    }

    /**
     * A person signed in a moment ago, fresh enough to add a first factor.
     *
     * @return array{0: \Tests\Fixtures\Models\Person, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession}
     *
     * @throws \Throwable
     */
    private function freshPerson(): array
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $this->reauthenticate($person, $session);

        return [$person, $session];
    }

    /**
     * A person with no factor signed in pending, allowed to enrol a passkey.
     *
     * @return array{0: \Tests\Fixtures\Models\Person, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 2: string}
     *
     * @throws \Throwable
     */
    private function pendingSignIn(): array
    {
        config()->set('mfa.applications.' . self::GUARD . '.requirement', 'always');
        config()->set('mfa.applications.' . self::GUARD . '.bootstrap', ['enabled' => true, 'types' => ['passkey']]);

        $person  = $this->createPerson();
        $result  = $this->attemptSignIn($person);
        $pending = $result->pending ?? self::fail('The sign-in did not wait for a further factor.');
        $session = $pending->session;

        self::assertInstanceOf(Model::class, $session);
        self::assertInstanceOf(EloquentSession::class, $session);
        self::assertNotNull($result->credential);

        return [$person, $session, $result->credential->reveal()];
    }

    /**
     * A person holding a passkey factor and a TOTP factor on an active session.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \Tests\Fixtures\Models\Person, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 2: \SineMacula\Laravel\Mfa\Models\Factor, 3: \SineMacula\Laravel\Mfa\Models\Factor}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function passkeyFactorBesideAnother(): array
    {
        [$person, $session] = $this->freshPerson();

        $this->requireNothing();

        self::assertTrue($this->registerForEnrolment($person, $session)->isRegistered());

        $factor = Factor::query()->sole();
        $kept   = $this->confirmedFactor($person);

        return [$person, $session, $factor, $kept];
    }

    /**
     * Have MFA ask nothing of the identity, so the session stays active.
     *
     * @return void
     */
    private function requireNothing(): void
    {
        config()->set('mfa.applications.' . self::GUARD . '.requirement', 'never');

        $this->app?->instance(IdentityRequirement::class, new class implements IdentityRequirement {
            /**
             * Ask nothing of the identity.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
             * @param  string  $application
             * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(MultiFactorAuthenticatable $identity, string $application): Requirement
            {
                return Requirement::none();
            }
        });
    }

    /**
     * Register the passkey for an MFA enrolment on the session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyRegistration
     *
     * @throws \Throwable
     */
    private function registerForEnrolment(Person $person, EloquentSession&Model $session): PasskeyRegistration
    {
        return $this->registerThroughAuthentication($person, self::CREDENTIAL, $this->bindingOf($person, $session, Purpose::ENROLLMENT));
    }

    /**
     * The binding of a ceremony on the person's session for the purpose.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofBinding
     */
    private function bindingOf(Person $person, EloquentSession&Model $session, Purpose $purpose): ProofBinding
    {
        return new ProofBinding($person, self::GUARD, $session->getSessionIdentifier(), $purpose);
    }

    /**
     * The id of the one passkey registered.
     *
     * @return string
     */
    private function passkeyId(): string
    {
        $id = Passkey::query()->sole()->getKey();

        self::assertIsString($id);

        return $id;
    }

    /**
     * The gate under test, resolved from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\PasskeyFactorGateAdapter
     */
    private function gate(): PasskeyFactorGateAdapter
    {
        $gate = $this->app?->make(PasskeyFactorGateAdapter::class);

        self::assertInstanceOf(PasskeyFactorGateAdapter::class, $gate);

        return $gate;
    }

    /**
     * A passkey as a registration shows it to the gate.
     *
     * @param  string  $credentialId
     * @return \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey
     */
    private static function registeredPasskey(#[\SensitiveParameter] string $credentialId = self::CREDENTIAL): RegisteredPasskey
    {
        return new RegisteredPasskey('passkey', $credentialId, self::RELYING_PARTY, new ObservedProperties(userPresence: true, userVerification: true), CarbonImmutable::now());
    }

    /**
     * Assert MFA's and the session's locks precede the passkeys statement.
     *
     * @param  string  $statement
     * @return void
     */
    private static function assertLocksPrecede(string $statement): void
    {
        $queries = array_column(DB::getQueryLog(), 'query');
        $passkey = array_key_first(array_filter($queries, static fn (string $query): bool => preg_match('/^' . $statement . ' [`"]?passkeys[`"]? /', $query) === 1));
        $locks   = array_filter($queries, static fn (string $query): bool => str_contains($query, 'for update'));
        $members = array_filter($locks, static fn (string $query): bool => str_contains($query, 'mfa_identity_states') || str_contains($query, 'mfa_factors'));

        $lastLock = array_key_last($locks);

        self::assertNotNull($passkey);
        self::assertNotSame([], $locks);
        self::assertNotSame([], $members);
        self::assertNotNull($lastLock);
        self::assertLessThan($passkey, $lastLock);
    }

    /**
     * Assert the call is refused by MFA, and return the refusal.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function refusal(\Closure $call): OperationRefusedException
    {
        try {
            $call();
        } catch (OperationRefusedException $exception) {
            return $exception;
        }

        self::fail('The change was not refused.');
    }
}
