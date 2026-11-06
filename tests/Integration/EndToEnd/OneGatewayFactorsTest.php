<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;
use SineMacula\Laravel\Iam\Delivery\DeliverySeams;
use SineMacula\Laravel\Iam\Delivery\EmailSenderAdapter;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;
use SineMacula\Laravel\Iam\Delivery\SmsSenderAdapter;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;
use SineMacula\Laravel\Iam\Testing\FakeSmsGateway;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\DeliversThroughGateways;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\RequiresNothing;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * End-to-end tests of an application that names one gateway only, keeping the
 * shipped routes, and offers that gateway's channel as an MFA factor type
 * (IAM-3.13): `laravel-authentication`'s one-time code sender stays unbound,
 * since its routes reach the other gateway too, so MFA keeps its own challenge
 * gateway and delivers its codes through its sender of the channel, pointed at
 * the gateway. Each factor is enrolled, challenged for a step-up and verified
 * with codes that arrive at the gateway, inside MFA's transaction, and none is
 * left for a delivery job that could never send it. Everything runs on MySQL
 * and PostgreSQL at READ COMMITTED and REPEATABLE READ.
 *
 * Each row names its own gateway and offers its own type before any provider
 * registers, read from the row the test runs with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaSeams::class)]
#[CoversClass(DeliverySeams::class)]
#[CoversClass(SmsSenderAdapter::class)]
#[CoversClass(EmailSenderAdapter::class)]
#[CoversClass(CodeMessage::class)]
final class OneGatewayFactorsTest extends TestCase
{
    use DeliversThroughGateways, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The number the SMS factor is enrolled with. */
    private const string PHONE = '+447700900457';

    /** @var string The address the email factor is enrolled with. */
    private const string ADDRESS = 'ada.single@example.test';

    /**
     * Queue `laravel-authentication`'s deliveries, so a code it issued would
     * wait for a job the test can count.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->queueDeliveries();
    }

    /**
     * Rows of `[isolation level, channel, destination]` for each delivered
     * factor type at each level.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Iam\Delivery\Enums\Channel, 2: string}>
     */
    public static function provideChannels(): iterable
    {
        foreach (self::provideIsolationLevels() as $name => [$level]) {
            yield $name . ', sms' => [$level, Channel::SMS, self::PHONE];

            yield $name . ', email' => [$level, Channel::EMAIL, self::ADDRESS];
        }
    }

    /**
     * A factor of the one gateway's channel is enrolled, challenged and
     * verified with codes that arrive at that gateway as MFA's, inside MFA's
     * own transaction, while nothing is queued for `laravel-authentication`'s
     * unbound one-time code sender and nothing reaches the other gateway.
     *
     * @param  string  $level
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  string  $destination
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChannels')]
    public function testAFactorOfTheOneGatewaysChannelIsDeliveredThroughIt(string $level, Channel $channel, string $destination): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        self::assertInstanceOf(PackageChallengeGateway::class, $this->app?->make(ChallengeGateway::class));
        self::assertFalse($this->app->bound(OneTimeCodeSender::class));

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $gateway = $this->gatewayOf($channel);

        $this->reauthenticate($person, $session);

        $start = Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::delivered($channel->value, $destination));

        self::assertTrue($start->hasStarted(), (string) $start->reason?->value);
        self::assertNotNull($start->grant);

        $enrolment = $gateway->sent()[0] ?? self::fail('No enrolment code arrived at the gateway.');

        self::assertSame(Source::MFA, $enrolment->source);
        self::assertSame(Purpose::ENROLLMENT, $enrolment->purpose);
        self::assertSame($destination, $enrolment->destination());
        self::assertTrue($person->is($enrolment->recipient()));
        self::assertTrue(Mfa::confirmEnrollment(self::servedCaller(), $start->grant, $enrolment->code->reveal())->isConfirmed());

        $factor = Factor::query()->where('destination', $destination)->sole();
        $sent   = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);
        $stepUp = $gateway->sent()[1] ?? self::fail('No step-up code arrived at the gateway.');

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);
        self::assertSame(Purpose::ADDITIONAL_FACTOR, $stepUp->purpose);
        $submission = Submission::challenge($factor->id, (string) $sent->challengeId, $stepUp->code->reveal());

        self::assertTrue(Mfa::verify(self::servedCaller(), $submission, MfaPurpose::STEP_UP)->isVerified());
        self::assertSame(0, $this->runDeliveries(), 'No code waits for a delivery job.');
        self::assertSame(0, DB::table('one_time_codes')->count());
        self::assertSame([], $this->otherGatewayThan($channel)->sent());
    }

    /**
     * Require no factor of anyone, so the session stays active once a factor is
     * enrolled and is stepped up with it.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $app->singleton(IdentityRequirement::class, RequiresNothing::class);
        $app->make('config')->set('mfa.applications.' . self::GUARD . '.requirement', 'never');
    }

    /**
     * Name the row's gateway alone, with the shipped routes, and offer its
     * channel as the one delivered factor type, before any provider registers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        assert($app instanceof Application);

        $channel = $this->providedData()[1] ?? null;

        assert($channel instanceof Channel);

        $config = $app->make(ConfigRepository::class);

        $config->set('iam.delivery', [
            'email' => $channel === Channel::EMAIL ? FakeEmailGateway::class : null,
            'sms'   => $channel === Channel::SMS ? FakeSmsGateway::class : null,
            'types' => ['email' => 'email', 'phone' => 'sms'],
        ]);
        $config->set('mfa.applications.' . self::GUARD . '.types', ['totp', $channel->value]);
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
}
