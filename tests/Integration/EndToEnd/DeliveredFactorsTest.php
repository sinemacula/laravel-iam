<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Iam\Mfa\ChallengeGatewayAdapter;
use SineMacula\Laravel\Iam\Mfa\CodeSenderAdapter;
use SineMacula\Laravel\Iam\Mfa\EventContextResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\FactorCodeCountersAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\ContextEvent;
use SineMacula\Laravel\Mfa\Events\EnrollmentStarted;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Events\FactorConfirmed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Codes\Concerns\DeliversFactorCodes;
use Tests\Fixtures\Mfa\RequiresNothing;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\TestCase;

/**
 * End-to-end tests of an MFA email factor and an SMS factor (IAM-3.9, IAM-3.12,
 * IAM-3.13), driven through MFA's public API with every adapter of this
 * package's bound: each code reaches the application's `laravel-authentication`
 * one-time code sender, whether `laravel-authentication` issues it or MFA's own
 * challenge gateway does. Everything runs on MySQL and PostgreSQL at READ
 * COMMITTED and REPEATABLE READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeGatewayAdapter::class)]
#[CoversClass(FactorCodeCountersAdapter::class)]
#[CoversClass(CodeSenderAdapter::class)]
#[CoversClass(EventContextResolverAdapter::class)]
final class DeliveredFactorsTest extends TestCase
{
    use DeliversFactorCodes, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The tenant the person's session was signed in to. */
    private const string TENANT = 'tenant-01JA4K';

    /** @var string A tenant a request claims, which nothing may carry. */
    private const string CLAIMED_TENANT = 'tenant-claimed';

    /** @var string The number the SMS factor is enrolled with. */
    private const string PHONE = '+447700900456';

    /** @var string The address the email factor is enrolled with. */
    private const string ADDRESS = 'ada.factor@example.test';

    /** @var list<\SineMacula\Laravel\Mfa\Contracts\MfaEvent> MFA's events, in the order dispatched. */
    private array $events = [];

    /**
     * Queue the deliveries, and record MFA's events as they are dispatched.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fakeFactorCodeDelivery();

        Event::listen(MfaEvent::class, function (MfaEvent $event): void {
            $this->events[] = $event;
        });
    }

    /**
     * Rows of `[isolation level, factor type, destination]` for each delivered
     * factor type at each level.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideDeliveredFactors(): iterable
    {
        foreach (self::provideIsolationLevels() as $name => [$level]) {
            yield $name . ', sms' => [$level, 'sms', self::PHONE];

            yield $name . ', email' => [$level, 'email', self::ADDRESS];
        }
    }

    /**
     * A delivered factor is enrolled, challenged and verified end to end: the
     * enrolment's code and the step-up's each reach the application's sender
     * once, from `laravel-authentication`'s queued delivery, and the step-up is
     * recorded on the session with the factor.
     *
     * @param  string  $level
     * @param  string  $type
     * @param  string  $destination
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeliveredFactors')]
    public function testADeliveredFactorIsEnrolledChallengedAndVerifiedThroughTheApplicationsSender(string $level, string $type, string $destination): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, $session] = $this->personInTenant();

        $factor    = $this->enrol($person, $session, $type, $destination);
        $enrolment = $this->codeSender()->sent()[0];

        self::assertSame(1, $this->codeSender()->count());
        $this->assertMessage($enrolment, $person, $type, $destination, CodePurpose::ENROLLMENT);

        $sent = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);
        self::assertSame(1, $this->codeSender()->count(), 'The code is delivered once the code has committed, by the queued job.');

        $stepUp = $this->deliverFactorCodes()[0] ?? self::fail('No step-up code was delivered.');

        self::assertSame(2, $this->codeSender()->count());
        $this->assertMessage($stepUp, $person, $type, $destination, CodePurpose::MFA);
        self::assertEquals($stepUp->expiresAt, $sent->expiresAt);

        $verified = Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, (string) $sent->challengeId, $stepUp->code->reveal()), MfaPurpose::STEP_UP);

        self::assertTrue($verified->isVerified(), (string) $verified->reason?->value);

        $proof = $this->proofsOf($session)[0];

        self::assertSame(AuthenticationPurpose::STEP_UP, $proof->purpose);
        self::assertSame($factor->id, $proof->factor);
        self::assertSame($destination, $proof->channel->reference);
        self::assertSame(0, self::storage()->transactionLevel());
    }

    /**
     * MFA's events about the enrolment and the step-up each carry the identity
     * and the application MFA names, and the session MFA names them made on,
     * with the principal it acts as and the tenant its row records, never the
     * tenant a request header or input claims; an event MFA names no sign-in
     * for carries none of them.
     *
     * @param  string  $level
     * @param  string  $type
     * @param  string  $destination
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeliveredFactors')]
    public function testMfasEventsCarryTheSessionTheyNameAndNoClaimedTenant(string $level, string $type, string $destination): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, $session] = $this->personInTenant();

        $request = $this->app?->make('request');

        self::assertInstanceOf(Request::class, $request);

        $request->headers->set('X-Tenant', self::CLAIMED_TENANT);
        $request->merge(['tenant_id' => self::CLAIMED_TENANT, 'tenant' => self::CLAIMED_TENANT]);

        $factor = $this->enrol($person, $session, $type, $destination);
        $sent   = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);

        $this->deliverFactorCodes();

        $code = $this->codeSender()->lastCodeFor($destination, CodePurpose::MFA) ?? self::fail('No step-up code was delivered.');

        self::assertTrue(Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, (string) $sent->challengeId, $code), MfaPurpose::STEP_UP)->isVerified());

        $dispatched = array_map(static fn (MfaEvent $event): string => $event::class, $this->events);

        foreach ([EnrollmentStarted::class, CodeSent::class, FactorConfirmed::class, VerificationPassed::class] as $expected) {
            self::assertContains($expected, $dispatched);
        }

        $named  = [SignIn::reference($session, self::GUARD), $person->getMorphClass(), EventContext::scalarKey($person->getKey()), self::TENANT];
        $naming = [];

        foreach ($this->events as $event) {

            self::assertInstanceOf(ContextEvent::class, $event);
            self::assertSame(self::GUARD, $event->context['application'], $event::class);
            self::assertSame($person->getMorphClass(), $event->context['identity_type'], $event::class);

            $carried = [$event->context['session_id'], $event->context['principal_type'], $event->context['principal_id'], $event->context['tenant_id']];

            self::assertContains($carried, [$named, [null, null, null, null]], $event::class);

            if ($carried !== $named) {
                continue;
            }

            $naming[] = $event::class;
        }

        foreach ([EnrollmentStarted::class, CodeSent::class, FactorConfirmed::class, VerificationPassed::class] as $expected) {
            self::assertContains($expected, $naming);
        }
    }

    /**
     * An application that keeps MFA's own challenge gateway has its codes sent
     * by MFA's senders, which hand each to the application's sender at once,
     * inside MFA's transaction, and the factor is enrolled, challenged and
     * verified with them.
     *
     * @param  string  $level
     * @param  string  $type
     * @param  string  $destination
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeliveredFactors')]
    #[DefineEnvironment('keepMfasOwnChallenges')]
    public function testWithMfasOwnChallengesTheCodesReachTheApplicationsSender(string $level, string $type, string $destination): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, $session] = $this->personInTenant();

        $this->reauthenticate($person, $session);

        $start     = Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::delivered($type, $destination));
        $enrolment = $this->codeSender()->sent()[0] ?? self::fail('No enrolment code was delivered.');

        self::assertTrue($start->hasStarted(), (string) $start->reason?->value);
        self::assertNotNull($start->grant);
        self::assertSame(0, $this->queuedDeliveries(), 'MFA\'s own codes never go through laravel-authentication\'s queue.');
        $this->assertMessage($enrolment, $person, $type, $destination, CodePurpose::ENROLLMENT);
        self::assertTrue(Mfa::confirmEnrollment(self::servedCaller(), $start->grant, $enrolment->code->reveal())->isConfirmed());

        $factor = Factor::query()->where('destination', $destination)->sole();
        $sent   = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);
        $stepUp = $this->codeSender()->sent()[1] ?? self::fail('No step-up code was delivered.');

        $this->assertMessage($stepUp, $person, $type, $destination, CodePurpose::MFA);
        $submission = Submission::challenge($factor->id, (string) $sent->challengeId, $stepUp->code->reveal());

        self::assertTrue(Mfa::verify(self::servedCaller(), $submission, MfaPurpose::STEP_UP)->isVerified());
    }

    /**
     * Keep MFA's own challenge gateway, bound as the application's before any
     * provider registers, so the binding rule keeps it.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    protected function keepMfasOwnChallenges(Application $app): void
    {
        $app->bind(ChallengeGateway::class, PackageChallengeGateway::class);
    }

    /**
     * Bind the application's sender, let the person's session act in the tenant
     * it records on every later judgement, as an application's tenancy would,
     * and require no factor of anyone, so the session stays active once a
     * factor is enrolled and is stepped up with it.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->defineFactorCodes($app);

        $app->singleton(TenantResolver::class, OpenTenancy::class);
        $app->singleton(TenantAccess::class, OpenTenancy::class);
        $app->singleton(IdentityRequirement::class, RequiresNothing::class);
        $app->make('config')->set('mfa.applications.' . self::GUARD . '.requirement', 'never');
    }

    /**
     * Assert a message is a code of the purpose for the person on the guard, to
     * the destination by the factor's channel.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage  $message
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $type
     * @param  string  $destination
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @return void
     */
    private function assertMessage(OneTimeCodeMessage $message, Person $person, string $type, string $destination, CodePurpose $purpose): void
    {
        self::assertSame($purpose, $message->purpose);
        self::assertSame($type, $message->type);
        self::assertSame($destination, $message->identifier);
        self::assertSame(self::GUARD, $message->guard);
        self::assertIsThePerson($person, $message->identity);
        self::assertTrue($message->expiresAt->isFuture());
    }

    /**
     * Enrol a delivered factor of the type to the destination on the session,
     * which proves its password again first: start the enrolment, deliver its
     * code and confirm it with the code the application's sender was given.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $type
     * @param  string  $destination
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     *
     * @throws \Throwable
     */
    private function enrol(Person $person, EloquentSession&Model $session, string $type, string $destination): Factor
    {
        $this->reauthenticate($person, $session);

        $start = Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::delivered($type, $destination));

        self::assertTrue($start->hasStarted(), (string) $start->reason?->value);
        self::assertNotNull($start->grant);
        self::assertCount(1, $this->deliverFactorCodes());

        $code = $this->codeSender()->lastCodeFor($destination, CodePurpose::ENROLLMENT) ?? self::fail('No enrolment code was delivered.');

        $confirmation = Mfa::confirmEnrollment(self::servedCaller(), $start->grant, $code);

        self::assertTrue($confirmation->isConfirmed(), (string) $confirmation->reason?->value);

        return Factor::query()->where('destination', $destination)->sole();
    }

    /**
     * A person signed in to the tenant, as a sign-in into a tenant records it
     * on the session's row, and acting on that session as a bearer request for
     * it would.
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
     * Reauthenticate the session with the person's password, so it is fresh
     * enough to add a factor.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     *
     * @throws \Throwable
     */
    private function reauthenticate(Person $person, EloquentSession&Model $session): void
    {
        $result = $this->sessions()->reauthenticate($session, 'password', ['email' => $person->email, 'password' => self::PASSWORD], self::client());

        self::assertTrue($result->isIssued(), sprintf('The session was not reauthenticated: [%s].', $result->reason->value ?? 'none'));
    }

    /**
     * The storage connection every member's tables live on.
     *
     * @return \Illuminate\Database\Connection
     */
    private static function storage(): Connection
    {
        return DB::connection();
    }
}
