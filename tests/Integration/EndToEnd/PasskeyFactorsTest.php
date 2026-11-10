<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Iam\Mfa\EventContextResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\PasskeyFactorGateAdapter;
use SineMacula\Laravel\Iam\Mfa\PasskeyGatewayAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\ContextEvent;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Events\PasskeyAssociated;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RegistersPasskeys;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\RequiresNothing;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\TestCase;

/**
 * End-to-end tests of a passkey as an MFA factor (IAM-3.10, IAM-3.12), driven
 * through `laravel-authentication`'s passkey service and MFA's public API as an
 * application's routes drive them, with every adapter of this package's bound
 * by the binding rule while the MFA application offers the `passkey` type.
 *
 * A passkey registered for an MFA enrolment becomes a confirmed passkey factor,
 * steps the session up through MFA, and, removed through
 * `laravel-authentication`, takes its factor and association with it in the
 * same change; removed as a factor through MFA instead, it stays a sign-in
 * passkey with no factor behind it, and its later removal asks MFA nothing.
 * Either way no factor is left without its passkey. MFA's events about it carry
 * the application MFA names and, where MFA names the sign-in the change was
 * made on, that session, the principal it acts as and its tenant. Everything
 * runs on MySQL and PostgreSQL at READ COMMITTED and REPEATABLE READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyFactorGateAdapter::class)]
#[CoversClass(PasskeyGatewayAdapter::class)]
#[CoversClass(EventContextResolverAdapter::class)]
final class PasskeyFactorsTest extends TestCase
{
    use MigratesMembers, RegistersPasskeys, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The passkey's credential id, in unpadded base64url. */
    private const string CREDENTIAL = 'ZW5kLXRvLWVuZC1wYXNza2V5';

    /** @var string The tenant the person's session was signed in to. */
    private const string TENANT = 'tenant-01JA5P';

    /** @var list<\SineMacula\Laravel\Mfa\Contracts\MfaEvent> MFA's events, in the order dispatched. */
    private array $events = [];

    /**
     * Record MFA's events as they are dispatched.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Event::listen(MfaEvent::class, function (MfaEvent $event): void {
            $this->events[] = $event;
        });
    }

    /**
     * A passkey registered for an enrolment is a confirmed passkey factor that
     * steps the session up through MFA; removed through
     * `laravel-authentication` once the session is stepped up with another
     * factor, it takes its factor and association with it, so MFA neither lists
     * nor challenges a factor without its passkey, and MFA's events about both
     * changes carry the application and the session they were made on, with its
     * principal and tenant.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAPasskeyRemovedThroughAuthenticationTakesItsFactorWithIt(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, $session] = $this->personInTenant();

        [$factor, $passkeyId] = $this->enrolPasskey($person, $session);

        $this->stepUpWithPasskey($factor);
        $this->stepUpWithAnotherFactor($person);

        $removal = $this->passkeys()->remove($person, $passkeyId, self::client());

        self::assertTrue($removal->isRemoved());
        self::assertNotNull($removal->completion, 'MFA removed the factor in the same change.');
        self::assertFalse(Passkey::query()->whereKey($passkeyId)->exists());
        self::assertNull(Factor::query()->find($factor->id));
        self::assertSame(0, PasskeyAssociation::query()->count());
        self::assertSame([], $this->gateway()->credentialIds($person));
        self::assertFalse(Mfa::requestAssertion(self::servedCaller(), $factor->id, Purpose::STEP_UP)->hasStarted());
        self::assertSame(0, DB::connection()->transactionLevel());

        $this->assertEventsCarryTheirSignIn($person, $session, [PasskeyAssociated::class, FactorRemoved::class]);
    }

    /**
     * A passkey factor removed through MFA, on a session stepped up with
     * another factor, leaves the passkey a sign-in passkey with no factor or
     * association behind it, still registered to the identity; its later
     * removal through `laravel-authentication` asks MFA nothing, answers no
     * completion, and leaves no passkey registered.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAPasskeyFactorRemovedThroughMfaLeavesOnlyASignInPasskey(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, $session] = $this->personInTenant();

        [$factor, $passkeyId] = $this->enrolPasskey($person, $session);

        $this->stepUpWithPasskey($factor);
        $this->stepUpWithAnotherFactor($person);

        $removed = Mfa::removeFactor(self::servedCaller(), $factor->id);

        self::assertTrue($removed->wasMade(), (string) $removed->reason?->value);
        self::assertNull(Factor::query()->find($factor->id));
        self::assertSame(0, PasskeyAssociation::query()->count());
        self::assertTrue(Passkey::query()->whereKey($passkeyId)->exists(), 'The passkey stays, for signing in.');
        self::assertSame([self::CREDENTIAL], $this->gateway()->credentialIds($person));

        $removal = $this->passkeys()->remove($person, $passkeyId, self::client());

        self::assertTrue($removal->isRemoved());
        self::assertNull($removal->completion);
        self::assertSame([], $this->gateway()->credentialIds($person));
        self::assertSame(0, Factor::query()->where('type', 'passkey')->count());

        $this->assertEventsCarryTheirSignIn($person, $session, [PasskeyAssociated::class, FactorRemoved::class]);
    }

    /**
     * Let the person's session act in the tenant it records on every later
     * judgement, and require no factor of anyone, so the session stays active
     * once the passkey is enrolled and is stepped up with it.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $app->singleton(TenantResolver::class, OpenTenancy::class);
        $app->singleton(TenantAccess::class, OpenTenancy::class);
        $app->singleton(IdentityRequirement::class, RequiresNothing::class);
        $app->make('config')->set('mfa.applications.' . self::GUARD . '.requirement', 'never');
    }

    /**
     * Register the passkey for an MFA enrolment on the session, which proves
     * its password again first, and return the factor it became and the
     * passkey's id.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return array{0: \SineMacula\Laravel\Mfa\Models\Factor, 1: string}
     *
     * @throws \Throwable
     */
    private function enrolPasskey(Person $person, EloquentSession&Model $session): array
    {
        $reauthenticated = $this->sessions()->reauthenticate($session, 'password', ['email' => $person->email, 'password' => self::PASSWORD], self::client());

        self::assertTrue($reauthenticated->isIssued(), $reauthenticated->reason->value ?? '');

        $binding      = new ProofBinding($person, self::GUARD, $session->getSessionIdentifier(), AuthenticationPurpose::ENROLLMENT);
        $registration = $this->registerPasskey($person, self::CREDENTIAL, $binding);

        self::assertTrue($registration->isRegistered(), $registration->status->value);
        self::assertNotNull($registration->factor);
        self::assertNotNull($registration->passkey);

        $factor = Factor::query()->findOrFail($registration->factor->factor);

        self::assertSame('passkey', $factor->getType());
        self::assertSame(FactorStatus::CONFIRMED, $factor->getStatus());
        self::assertSame(self::CREDENTIAL, $factor->getCredentialReference());
        self::assertSame([self::CREDENTIAL], $this->gateway()->credentialIds($person));

        return [$factor, $registration->passkey->id];
    }

    /**
     * Step the session up through MFA with an assertion of the passkey factor,
     * answered by the virtual authenticator, failing unless it verifies.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return void
     *
     * @throws \Throwable
     */
    private function stepUpWithPasskey(Factor $factor): void
    {
        $request = Mfa::requestAssertion(self::servedCaller(), $factor->id, Purpose::STEP_UP);

        self::assertTrue($request->hasStarted(), $request->reason->value ?? '');

        $challenge = $request->options['challenge'];
        $options   = $request->options['options'];

        self::assertIsString($challenge);
        self::assertIsArray($options);

        /** @var array<string, mixed> $options */
        $response = ['challenge' => $challenge, 'credential' => $this->authenticator()->get($options, self::CREDENTIAL)];
        $result   = Mfa::verify(self::servedCaller(), Submission::assertion($factor->id, $response), Purpose::STEP_UP);

        self::assertTrue($result->isVerified(), $result->detail ?? (string) $result->reason?->value);
    }

    /**
     * Give the person an authenticator app factor beside the passkey, and step
     * the session up with it through MFA, as removing a factor asks of a
     * session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return void
     *
     * @throws \Throwable
     */
    private function stepUpWithAnotherFactor(Person $person): void
    {
        $kept = Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => IdentityReference::of($person)->key,
            'label'                => 'Phone',
            'status'               => FactorStatus::CONFIRMED->value,
            'application'          => self::GUARD,
            'confirmed_at'         => CarbonImmutable::now(),
        ]);

        $result = Mfa::verify(self::servedCaller(), Submission::factor($kept->id, AuthenticatorApp::code($kept)), Purpose::STEP_UP);

        self::assertTrue($result->isVerified(), (string) $result->reason?->value);
    }

    /**
     * Assert every MFA event dispatched carries the application, and either the
     * session it was made on, with the principal it acts as and its tenant, or
     * none of them where MFA names no sign-in; and that the events named were
     * among them, each naming the session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  list<class-string<\SineMacula\Laravel\Mfa\Contracts\MfaEvent>>  $expected
     * @return void
     *
     * @throws \Throwable
     */
    private function assertEventsCarryTheirSignIn(Person $person, EloquentSession&Model $session, array $expected): void
    {
        $named  = [SignIn::reference($session, self::GUARD), $person->getMorphClass(), EventContext::scalarKey($person->getKey()), self::TENANT];
        $naming = [];

        foreach ($this->events as $event) {

            self::assertInstanceOf(ContextEvent::class, $event);
            self::assertSame(self::GUARD, $event->context['application'], $event::class);

            $carried = [$event->context['session_id'], $event->context['principal_type'], $event->context['principal_id'], $event->context['tenant_id']];

            self::assertContains($carried, [$named, [null, null, null, null]], $event::class);

            if ($carried !== $named) {
                continue;
            }

            $naming[] = $event::class;
        }

        foreach ($expected as $class) {
            self::assertContains($class, $naming);
        }
    }

    /**
     * A person signed in to the tenant, as a sign-in into a tenant records it
     * on the session's row, and acting on that session.
     *
     * @return array{0: \Tests\Fixtures\Models\Person, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession}
     *
     * @throws \Throwable
     */
    private function personInTenant(): array
    {
        $person  = $this->createPerson();
        $session = $this->signIn($person)->record;

        $session->forceFill([$session->getTenantIdName() => self::TENANT])->save();

        $this->actingOnSession($session, self::GUARD);

        return [$person, $session];
    }

    /**
     * MFA's passkey gateway, as bound.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway
     */
    private function gateway(): PasskeyGateway
    {
        $gateway = $this->app?->make(PasskeyGateway::class);

        self::assertInstanceOf(PasskeyGateway::class, $gateway);

        return $gateway;
    }
}
