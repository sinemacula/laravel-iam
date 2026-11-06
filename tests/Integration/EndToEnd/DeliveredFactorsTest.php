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
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;
use SineMacula\Laravel\Iam\Delivery\EmailSenderAdapter;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;
use SineMacula\Laravel\Iam\Delivery\OneTimeCodeSenderAdapter;
use SineMacula\Laravel\Iam\Delivery\SmsSenderAdapter;
use SineMacula\Laravel\Iam\Mfa\ChallengeGatewayAdapter;
use SineMacula\Laravel\Iam\Mfa\EventContextResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\FactorCodeCountersAdapter;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\ContextEvent;
use SineMacula\Laravel\Mfa\Events\EnrollmentStarted;
use SineMacula\Laravel\Mfa\Events\FactorConfirmed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Exceptions\CodeDeliveryFailedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\DeliversThroughGateways;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\RequiresNothing;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\TestCase;

/**
 * End-to-end tests of an MFA email factor and an SMS factor (IAM-3.9, IAM-3.12,
 * IAM-3.13), driven through MFA's public API as an application's routes drive
 * it, with every adapter of this package's bound by the binding rule and both
 * gateways named.
 *
 * Each factor is enrolled, challenged for a step-up and verified, every code
 * issued and checked by `laravel-authentication`'s factor codes under MFA's
 * challenge counters, and delivered once, through the application's gateway of
 * the factor's channel, as this package's one `CodeMessage`; MFA's own senders
 * never run. MFA's events about it carry the identity and the application MFA
 * names, and no tenant or session: neither the caller's validated session's,
 * which MFA hands the event context no sign-in to name, nor one a request
 * claims. A gateway that throws fails `laravel-authentication`'s delivery job
 * once the code has committed, so the code stays issued and the queue's retry
 * delivers it; an application that keeps MFA's own challenge gateway has its
 * codes delivered inside MFA's transaction, so there a gateway that throws
 * rolls the code back with the enrolment it was for. Everything runs on MySQL
 * and PostgreSQL at READ COMMITTED and REPEATABLE READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeGatewayAdapter::class)]
#[CoversClass(FactorCodeCountersAdapter::class)]
#[CoversClass(OneTimeCodeSenderAdapter::class)]
#[CoversClass(SmsSenderAdapter::class)]
#[CoversClass(EmailSenderAdapter::class)]
#[CoversClass(EventContextResolverAdapter::class)]
#[CoversClass(CodeMessage::class)]
final class DeliveredFactorsTest extends TestCase
{
    use DeliversThroughGateways, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

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

        $this->queueDeliveries();

        Event::listen(MfaEvent::class, function (MfaEvent $event): void {
            $this->events[] = $event;
        });
    }

    /**
     * Rows of `[isolation level, factor type, channel, destination]` for each
     * delivered factor type at each level.
     *
     * @return iterable<string, array{0: string, 1: string, 2: \SineMacula\Laravel\Iam\Delivery\Enums\Channel, 3: string}>
     */
    public static function provideDeliveredFactors(): iterable
    {
        foreach (self::provideIsolationLevels() as $name => [$level]) {
            yield $name . ', sms' => [$level, 'sms', Channel::SMS, self::PHONE];

            yield $name . ', email' => [$level, 'email', Channel::EMAIL, self::ADDRESS];
        }
    }

    /**
     * A delivered factor is enrolled, challenged and verified end to end: the
     * enrolment's code and the step-up's each reach the application's gateway
     * of the factor's channel once, as this package's message from
     * `laravel-authentication` for the person on the guard, and the step-up is
     * recorded on the session with the factor. Nothing reaches the other
     * gateway, and MFA's own senders deliver nothing.
     *
     * @param  string  $level
     * @param  string  $type
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  string  $destination
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeliveredFactors')]
    public function testADeliveredFactorIsEnrolledChallengedAndVerifiedThroughTheGateway(string $level, string $type, Channel $channel, string $destination): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, $session] = $this->personInTenant();

        $factor    = $this->enrol($person, $session, $type, $destination);
        $gateway   = $this->gatewayOf($channel);
        $enrolment = $gateway->sent()[0];

        self::assertCount(1, $gateway->sent());
        $this->assertMessage($enrolment, $person, $channel, $type, $destination, CodePurpose::ENROLLMENT, Purpose::ENROLLMENT);

        $sent = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);
        self::assertSame([$enrolment], $gateway->sent(), 'The code is delivered once the code has committed, by the queued job.');
        self::assertSame(1, $this->runDeliveries());
        self::assertCount(2, $gateway->sent());

        $stepUp = $gateway->sent()[1];

        $this->assertMessage($stepUp, $person, $channel, $type, $destination, CodePurpose::MFA, Purpose::ADDITIONAL_FACTOR);
        self::assertTrue($stepUp->expiresAt->equalTo($sent->expiresAt));

        $verified = Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, (string) $sent->challengeId, $stepUp->code->reveal()), MfaPurpose::STEP_UP);

        self::assertTrue($verified->isVerified(), (string) $verified->reason?->value);

        $proof = $this->proofsOf($session)[0];

        self::assertSame(AuthenticationPurpose::STEP_UP, $proof->purpose);
        self::assertSame($factor->id, $proof->factor);
        self::assertSame($destination, $proof->channel->reference);
        self::assertSame([], $this->otherGatewayThan($channel)->sent());
        self::assertSame(0, self::storage()->transactionLevel());
    }

    /**
     * MFA's events about the enrolment and the step-up each carry the identity
     * and the application MFA names, and no tenant or session: neither those of
     * the caller's validated session, which MFA hands the event context no
     * sign-in to name, nor the tenant a request header or input claims.
     *
     * @param  string  $level
     * @param  string  $type
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  string  $destination
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeliveredFactors')]
    public function testMfasEventsCarryNoTenantOrSessionTheyAreNotHanded(string $level, string $type, Channel $channel, string $destination): void
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

        $this->runDeliveries();

        $code = $this->gatewayOf($channel)->lastCodeTo($destination, Purpose::ADDITIONAL_FACTOR) ?? self::fail('No step-up code was delivered.');

        self::assertTrue(Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, (string) $sent->challengeId, $code), MfaPurpose::STEP_UP)->isVerified());

        $dispatched = array_map(static fn (MfaEvent $event): string => $event::class, $this->events);

        foreach ([EnrollmentStarted::class, CodeSent::class, FactorConfirmed::class, VerificationPassed::class] as $expected) {
            self::assertContains($expected, $dispatched);
        }

        foreach ($this->events as $event) {

            self::assertInstanceOf(ContextEvent::class, $event);
            self::assertNull($event->context['tenant_id'], $event::class);
            self::assertSame(self::GUARD, $event->context['application'], $event::class);
            self::assertNull($event->context['session_id'], $event::class);
            self::assertSame($person->getMorphClass(), $event->context['identity_type'], $event::class);
        }
    }

    /**
     * A gateway that throws fails `laravel-authentication`'s delivery job with
     * its exception, after MFA has reported the code sent: the code committed
     * before the job ran, so it stays issued, unused, and the queue's retry of
     * the job delivers that same code, which then verifies.
     *
     * @param  string  $level
     * @param  string  $type
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  string  $destination
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeliveredFactors')]
    public function testAFailedDeliveryLeavesTheCodeIssuedForTheQueuesRetry(string $level, string $type, Channel $channel, string $destination): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, $session] = $this->personInTenant();

        $factor  = $this->enrol($person, $session, $type, $destination);
        $gateway = $this->gatewayOf($channel);
        $failure = new \RuntimeException('The provider refused the message.');
        $codes   = $this->codes();

        $gateway->failNext($failure);

        $sent = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);

        self::assertTrue($sent->wasSent(), 'MFA reports the code sent once it is issued and queued.');
        self::assertSame($failure, $this->assertDeliveryFails(\RuntimeException::class));
        self::assertCount(1, $gateway->sent(), 'Only the enrolment\'s code was delivered.');
        self::assertSame($codes + 1, $this->codes(), 'The step-up\'s code stays issued.');

        $this->retryLastDelivery();

        $message = $gateway->sent()[1] ?? self::fail('The retry delivered nothing.');

        self::assertSame(CodePurpose::MFA, $message->memberPurpose);

        $verified = Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, (string) $sent->challengeId, $message->code->reveal()), MfaPurpose::STEP_UP);

        self::assertTrue($verified->isVerified(), (string) $verified->reason?->value);
    }

    /**
     * An application that keeps MFA's own challenge gateway has its codes
     * delivered by MFA's senders, pointed at the same gateways, inside MFA's
     * transaction: a gateway that throws fails the enrolment's start and rolls
     * back the code and the pending factor with it, so nothing is left to
     * confirm; started again, the code reaches the gateway as this package's
     * message from MFA, naming the factor with its destination masked, and the
     * factor is enrolled, challenged and verified.
     *
     * @param  string  $level
     * @param  string  $type
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  string  $destination
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeliveredFactors')]
    #[DefineEnvironment('keepMfasOwnChallenges')]
    public function testWithMfasOwnChallengesAFailedDeliveryRollsTheCodeBack(string $level, string $type, Channel $channel, string $destination): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$person, $session] = $this->personInTenant();

        $this->reauthenticate($person, $session);

        $gateway = $this->gatewayOf($channel)->failNext();
        $request = EnrollmentRequest::delivered($type, $destination);
        $thrown  = rescue(static fn (): mixed => Mfa::startEnrollment(self::servedCaller(), $request), static fn (\Throwable $exception): \Throwable => $exception, false);

        self::assertInstanceOf(CodeDeliveryFailedException::class, $thrown);
        self::assertSame(0, Factor::query()->count(), 'The pending factor rolls back with its code.');
        self::assertSame(0, DB::table('mfa_codes')->count(), 'MFA keeps no code it could not deliver.');
        self::assertSame([], $gateway->sent());
        self::assertSame(0, self::storage()->transactionLevel());

        $start = Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::delivered($type, $destination));

        self::assertTrue($start->hasStarted(), (string) $start->reason?->value);
        self::assertNotNull($start->grant);
        self::assertSame(0, $this->runDeliveries(), 'MFA\'s own codes never go through laravel-authentication\'s queue.');

        $enrolment = $gateway->sent()[0] ?? self::fail('No enrolment code was delivered.');

        self::assertSame(Source::MFA, $enrolment->source);
        self::assertSame(MfaPurpose::ENROLLMENT, $enrolment->memberPurpose);
        self::assertSame(Purpose::ENROLLMENT, $enrolment->purpose);
        self::assertSame($channel, $enrolment->channel);
        self::assertSame($destination, $enrolment->destination());
        self::assertNotNull($enrolment->factor);
        self::assertNotSame($destination, $enrolment->factor->maskedDestination);
        self::assertTrue($person->is($enrolment->recipient()));

        self::assertTrue(Mfa::confirmEnrollment(self::servedCaller(), $start->grant, $enrolment->code->reveal())->isConfirmed());

        $factor = Factor::query()->where('destination', $destination)->sole();
        $sent   = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);
        $stepUp = $gateway->sent()[1] ?? self::fail('No step-up code was delivered.');

        self::assertSame(MfaPurpose::STEP_UP, $stepUp->memberPurpose);
        self::assertSame(Purpose::ADDITIONAL_FACTOR, $stepUp->purpose);
        $submission = Submission::challenge($factor->id, (string) $sent->challengeId, $stepUp->code->reveal());

        self::assertTrue(Mfa::verify(self::servedCaller(), $submission, MfaPurpose::STEP_UP)->isVerified());
        self::assertSame([], $this->otherGatewayThan($channel)->sent());
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
     * Let the person's session act in the tenant it records on every later
     * judgement, as an application's tenancy would, and require no factor of
     * anyone, so the session stays active once a factor is enrolled and is
     * stepped up with it.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $app->singleton(TenantResolver::class, OpenTenancy::class);
        $app->singleton(TenantAccess::class, OpenTenancy::class);
        $app->singleton(IdentityRequirement::class, RequiresNothing::class);
        $app->make('config')->set('mfa.applications.' . self::GUARD . '.requirement', 'never');
    }

    /**
     * Offer the delivered factor types beside TOTP.
     *
     * @return list<string>
     */
    #[\Override]
    protected function mfaTypes(): array
    {
        return ['totp', 'sms', 'email'];
    }

    /**
     * Name both gateways before any provider registers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        assert($app instanceof Application);

        $this->nameTheGateways($app);
    }

    /**
     * Assert a message is this package's from `laravel-authentication`, for the
     * person on the guard, to the destination on the channel, for the purposes
     * given, naming no factor.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\CodeMessage  $message
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  string  $type
     * @param  string  $destination
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $memberPurpose
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Purpose  $purpose
     * @return void
     */
    private function assertMessage(CodeMessage $message, Person $person, Channel $channel, string $type, string $destination, CodePurpose $memberPurpose, Purpose $purpose): void
    {
        self::assertSame(Source::AUTHENTICATION, $message->source);
        self::assertSame($memberPurpose, $message->memberPurpose);
        self::assertSame($purpose, $message->purpose);
        self::assertSame($channel, $message->channel);
        self::assertSame($type, $message->type);
        self::assertSame($destination, $message->destination());
        self::assertSame(self::GUARD, $message->application);
        self::assertTrue($person->is($message->recipient()));
        self::assertNull($message->factor);
        self::assertTrue($message->expiresAt->isFuture());
    }

    /**
     * Enrol a delivered factor of the type to the destination on the session,
     * which proves its password again first: start the enrolment, deliver its
     * code and confirm it with the code the gateway was given.
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
        self::assertSame(1, $this->runDeliveries());

        $code = $this->gatewayOf(Channel::from($type))->lastCodeTo($destination, Purpose::ENROLLMENT) ?? self::fail('No enrolment code was delivered.');

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
     * How many codes `laravel-authentication` keeps.
     *
     * @return int
     */
    private function codes(): int
    {
        return DB::table('one_time_codes')->count();
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
