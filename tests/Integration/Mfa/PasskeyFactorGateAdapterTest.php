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
 * Integration tests for `laravel-authentication`'s passkey factor gate calling
 * MFA's passkey change gate inside the passkey transaction (IAM-3.10), with
 * every adapter between the two members bound by this package's binding rule,
 * as an application gets them while its MFA application offers passkeys.
 *
 * Passkeys are registered and removed through `laravel-authentication`'s public
 * passkey service, as a browser and an application would, so the gate runs in
 * that service's own transaction: a registration bound for an MFA enrolment
 * becomes a confirmed factor with its recovery codes and the session judged
 * again, its completion reaching the registration's caller; a removal removes
 * the factor in the same change, so no factor is left without its passkey, and
 * a refusal of either keeps nothing. MFA's identity and factor locks are taken
 * before the passkey's row is written or deleted, on MySQL and PostgreSQL at
 * READ COMMITTED and REPEATABLE READ.
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
     * A passkey registered for an MFA enrolment on a session fresh enough for a
     * first factor becomes a confirmed passkey factor of the person's, under
     * its credential and label, and the registration answers MFA's factor and
     * its whole result, with `laravel-authentication`'s judgement of the active
     * session again, which the new factor returns to pending.
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
     * A registration whose options were asked for without a binding stays a
     * sign-in passkey: MFA is not asked, and no factor is made.
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
     * A registration bound for anything but an enrolment is refused, keeping no
     * passkey and no factor.
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
     * A passkey registered for the enrolment of a pending sign-in (a bootstrap
     * enrolment, MFA requiring a factor of someone who has none), handed that
     * sign-in's pending credential, becomes a confirmed passkey factor in the
     * same change, and its proof satisfies the pending session, which
     * activates: the registration answers MFA's result with the verification,
     * whose completion is `laravel-authentication`'s signed-in result.
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
     * A bootstrap enrolment handed a pending credential that names no pending
     * sign-in is answered `pending_invalid` by `laravel-authentication`, before
     * the gate is asked: no passkey, factor or association is kept, and the
     * session stays pending.
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
     * A bootstrap enrolment is served to the client the registration was handed
     * and satisfies the pending session its credential names, though a request
     * bound in the container comes from another client and carries another
     * pending sign-in's credential: MFA's events about it, and the activated
     * session's last use, describe the handed client, and the other sign-in
     * stays pending.
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
     * Rows of `[whose]` for a pending credential the gate is handed that names
     * no pending sign-in of the identity registering.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideForeignPendingCredentials(): iterable
    {
        yield 'none' => ['none'];

        yield 'another identity\'s' => ['another'];
    }

    /**
     * A pending credential the gate is handed that names no pending sign-in of
     * the identity registering, which `laravel-authentication` refuses before
     * asking the gate, is refused as `not_found` all the same, by throwing
     * inside the transaction: no factor is made.
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
     * A registration MFA refuses, on a session not fresh enough to add a first
     * factor, keeps neither the passkey nor any factor.
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
     * Removing a passkey factor through `laravel-authentication` removes the
     * factor and its association in the same change, on a fresh step-up with
     * another factor, and answers `laravel-authentication`'s judgement of the
     * session, which the removal's caller gets back.
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
     * A removal MFA refuses, on a session never stepped up, keeps the passkey,
     * its factor and its association.
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
     * Removing a sign-in passkey, associated as no factor, answers no
     * completion and removes the passkey alone.
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
     * MFA's identity state and factor locks, and the session's row, are taken
     * before the passkey's row is written on registration, and before it is
     * deleted on removal.
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
     * A request bound in the container never reaches the change: though it
     * comes from another client and carries another person's pending sign-in
     * credential, the registration and the removal are judged as the active
     * caller `laravel-authentication`'s values name, on the application it
     * names, and MFA's events about both describe that identity on that
     * application, on the sign-in the change was made on, served to the client
     * the registration and the removal were handed, never the request's.
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
     * An identity MFA cannot hold factors for holds no passkey factor: nothing
     * is associated for it or removed.
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
     * MFA associates nothing on an application that does not offer passkeys, so
     * the registration stays a sign-in passkey.
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
     * A binding whose session is neither a non-empty string nor an integer
     * cannot be resolved, and throws inside the transaction.
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
     * The identity registering passkeys, signed in and acting on its session on
     * the guard, whose MFA application offers passkeys.
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
     * Register a passkey with the credential id through
     * `laravel-authentication`'s passkey service, bound for an MFA enrolment on
     * the gated identity's session, so the gate is asked.
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
     * A person signed in a moment ago and acting on the session, fresh enough
     * to add a first factor.
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
     * A person with no factor signed in pending, MFA requiring a factor of
     * everyone and allowing a pending session to enrol a passkey as its first,
     * with the pending session and its credential.
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
     * A person holding a passkey factor, registered for an enrolment on an
     * active session that stays active, and a TOTP factor beside it.
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
     * From now on, have MFA ask nothing of the identity, neither as the
     * application's requirement nor as its own, so a session judged again after
     * a factor change stays active.
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
     * @return \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey
     */
    private static function registeredPasskey(): RegisteredPasskey
    {
        return new RegisteredPasskey('passkey', self::CREDENTIAL, self::RELYING_PARTY, new ObservedProperties(userPresence: true, userVerification: true), CarbonImmutable::now());
    }

    /**
     * Assert every lock of MFA's identity state, its factors and the session
     * precedes the first statement on the passkeys' table of the kind given.
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
