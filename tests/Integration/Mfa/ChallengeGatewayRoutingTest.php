<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;
use SineMacula\Laravel\Iam\Mfa\ChallengeGatewayAdapter;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\DeliversThroughGateways;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Codes\Concerns\ArrangesDeliveredFactors;
use Tests\Fixtures\Mfa\Codes\RecordingCodeDriver;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for which path MFA's challenge gateway sends each code on
 * (IAM-3.9, IAM-3.13), with both gateways named and the challenge gateway
 * adapter bound, as an application that names them runs: only a factor of MFA's
 * own `sms` or `email` type, built by MFA's own driver over this package's
 * sender of its channel, is sent through `laravel-authentication`'s factor
 * codes. A driver the application registers through `Mfa::extend()`, whether it
 * overrides a shipped type or adds a type of its own of any channel kind,
 * delivers its codes itself, inside MFA's transaction, as MFA's contract asks;
 * so does MFA's own driver over a sender of the application's, whether bound in
 * the container or handed to the driver through `Mfa::extend()`, and MFA's own
 * driver registered under another type, whose codes reach the gateway as that
 * type's. With no one-time code sender bound, MFA sends every code itself. A
 * code sent on either path is checked on the same one. They run on every
 * database, and the application's own driver also at READ COMMITTED and
 * REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeGatewayAdapter::class)]
final class ChallengeGatewayRoutingTest extends TestCase
{
    use ArrangesDeliveredFactors, DeliversThroughGateways, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string A factor type of the application's own, delivered by its own driver. */
    private const string PUSH = 'push';

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
     * Rows of `[factor type, channel kind]`: each shipped delivered type, with
     * the kind its driver states.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Mfa\Enums\ChannelKind}>
     */
    public static function provideShippedTypes(): iterable
    {
        yield 'sms' => ['sms', ChannelKind::SMS];

        yield 'email' => ['email', ChannelKind::EMAIL];
    }

    /**
     * A driver the application registers over a shipped type is the one that
     * delivers its codes, once, inside MFA's transaction: no code is issued by
     * `laravel-authentication`, nothing reaches either gateway, and the code
     * the driver delivered verifies.
     *
     * @param  string  $type
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideShippedTypes')]
    public function testAnApplicationsDriverOfAShippedTypeDeliversItsCodes(string $type, ChannelKind $kind): void
    {
        $this->assertTheDriverDeliversItsCodes($type, $kind);
    }

    /**
     * Rows of `[isolation level, factor type, channel kind]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: \SineMacula\Laravel\Mfa\Enums\ChannelKind}>
     */
    public static function provideShippedTypesAtEachLevel(): iterable
    {
        foreach (self::provideIsolationLevels() as $name => [$level]) {
            foreach (self::provideShippedTypes() as $type => [, $kind]) {
                yield $name . ', ' . $type => [$level, $type, $kind];
            }
        }
    }

    /**
     * A driver the application registers over a shipped type delivers its codes
     * inside MFA's transaction at each isolation level.
     *
     * @param  string  $level
     * @param  string  $type
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideShippedTypesAtEachLevel')]
    public function testAnApplicationsDriverDeliversInsideMfasTransactionAtEachLevel(string $level, string $type, ChannelKind $kind): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $depth = $this->assertTheDriverDeliversItsCodes($type, $kind);

        self::assertGreaterThan(0, $depth, 'The driver must deliver inside MFA\'s transaction.');
    }

    /**
     * A type of the application's own, whose driver states a channel kind that
     * is neither SMS nor email, is sent and checked by MFA, never refused for
     * its kind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATypeOfTheApplicationsOwnOfAnotherChannelKindIsDeliveredByItsDriver(): void
    {
        config()->set('mfa.applications.' . self::GUARD . '.types', ['totp', 'sms', 'email', self::PUSH]);

        $this->assertTheDriverDeliversItsCodes(self::PUSH, ChannelKind::EXTERNAL_PROVIDER, 'device-token-1');
    }

    /**
     * Rows of `[factor type]`: each shipped delivered type.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideShippedTypeNames(): iterable
    {
        yield 'sms' => ['sms'];

        yield 'email' => ['email'];
    }

    /**
     * MFA's own driver of a shipped type, registered through `Mfa::extend()`
     * under its own name over a sender of the application's own, delivers
     * through that sender while the container's sender of its channel is still
     * this package's: no code is issued by `laravel-authentication`, nothing
     * reaches either gateway, and the code the sender was given verifies.
     *
     * @param  string  $type
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideShippedTypeNames')]
    public function testMfasDriverExtendedOverASenderOfTheApplicationsOwnDeliversThroughThatSender(string $type): void
    {
        $sender = $type === 'sms' ? new FakeSmsSender : new FakeEmailSender;

        Mfa::extend($type, static fn (): EmailDriver|SmsDriver => $sender instanceof FakeSmsSender ? new SmsDriver($sender) : new EmailDriver($sender));

        $person = $this->signedInPerson();
        $factor = $this->deliveredFactor($person, $type);
        $sent   = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);
        self::assertCount(1, $sender->sent(), 'The application\'s own sender must deliver the code.');
        $this->assertNothingReachedAuthentication();

        $code = $sender->lastCodeTo(self::deliveredDestination($person, $type)) ?? self::fail('No code reached the sender.');

        self::assertTrue(Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, (string) $sent->challengeId, $code), MfaPurpose::STEP_UP)->isVerified());
    }

    /**
     * MFA's own driver of a shipped type, built over a sender the application
     * binds once the application has booted, delivers through that sender: no
     * code is issued by `laravel-authentication`, nothing reaches either
     * gateway, and the code the sender was given verifies.
     *
     * @param  string  $type
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideShippedTypeNames')]
    public function testMfasDriverOverASenderTheApplicationBindsDeliversThroughThatSender(string $type): void
    {
        $sender = $type === 'sms' ? FakeSmsSender::fake($this->app) : FakeEmailSender::fake($this->app);
        $person = $this->signedInPerson();
        $factor = $this->deliveredFactor($person, $type);
        $sent   = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);
        self::assertCount(1, $sender->sent());
        $this->assertNothingReachedAuthentication();

        $code = $sender->lastCodeTo(self::deliveredDestination($person, $type)) ?? self::fail('No code reached the sender.');

        self::assertTrue(Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, (string) $sent->challengeId, $code), MfaPurpose::STEP_UP)->isVerified());
    }

    /**
     * MFA's own SMS driver registered under a type of the application's own is
     * sent by MFA, through this package's sender, so its code reaches the SMS
     * gateway at once as that type's, with the factor it is for, never as a
     * plain SMS code of `laravel-authentication`'s.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfasDriverUnderAnotherTypeReachesTheGatewayAsThatType(): void
    {
        config()->set('mfa.applications.' . self::GUARD . '.types', ['totp', 'sms', 'email', 'voice']);

        Mfa::extend('voice', static fn (Container $app): SmsDriver => new SmsDriver($app->make(SmsSender::class)));

        $person  = $this->signedInPerson();
        $factor  = $this->deliveredFactor($person, 'voice');
        $sent    = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);
        $message = $this->gatewayOf(Channel::SMS)->sent()[0] ?? self::fail('No code reached the SMS gateway.');

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);
        self::assertSame(Source::MFA, $message->source);
        self::assertSame('voice', $message->type);
        self::assertSame($factor->id, $message->factor?->id);
        self::assertSame(0, $this->runDeliveries(), 'No code waits for a delivery job.');
        $submission = Submission::challenge($factor->id, (string) $sent->challengeId, $message->code->reveal());

        self::assertTrue(Mfa::verify(self::servedCaller(), $submission, MfaPurpose::STEP_UP)->isVerified());
    }

    /**
     * With no one-time code sender bound, MFA sends even a shipped type's code
     * itself, through this package's sender, so it reaches the gateway at once
     * and verifies, rather than go to a sender that is not there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoOneTimeCodeSenderBoundMfaSendsItsCodesItself(): void
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        unset($app[OneTimeCodeSender::class]);

        self::assertInstanceOf(ChallengeGatewayAdapter::class, $this->resolved(ChallengeGateway::class));
        self::assertFalse($app->bound(OneTimeCodeSender::class));

        $person  = $this->signedInPerson();
        $factor  = $this->deliveredFactor($person);
        $sent    = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);
        $message = $this->gatewayOf(Channel::SMS)->sent()[0] ?? self::fail('No code reached the SMS gateway.');

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);
        self::assertSame(Source::MFA, $message->source);
        self::assertSame(Purpose::ADDITIONAL_FACTOR, $message->purpose);
        self::assertSame(0, DB::table('one_time_codes')->count());
        $submission = Submission::challenge($factor->id, (string) $sent->challengeId, $message->code->reveal());

        self::assertTrue(Mfa::verify(self::servedCaller(), $submission, MfaPurpose::STEP_UP)->isVerified());
    }

    /**
     * A shipped type's code, with MFA's own driver over this package's sender,
     * still goes through `laravel-authentication`: it is issued there and waits
     * for its delivery job, which takes it to the gateway of its channel.
     *
     * @param  string  $type
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideShippedTypeNames')]
    public function testAShippedTypeWithMfasDriverGoesThroughAuthentication(string $type): void
    {
        $person = $this->signedInPerson();
        $factor = $this->deliveredFactor($person, $type);
        $sent   = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);
        self::assertSame(1, DB::table('one_time_codes')->count());
        self::assertSame([], $this->gatewayOf(Channel::from($type))->sent());
        self::assertSame(1, $this->runDeliveries());

        $message = $this->gatewayOf(Channel::from($type))->sent()[0] ?? self::fail('No code reached the gateway.');

        self::assertSame(Source::AUTHENTICATION, $message->source);
        $submission = Submission::challenge($factor->id, (string) $sent->challengeId, $message->code->reveal());

        self::assertTrue(Mfa::verify(self::servedCaller(), $submission, MfaPurpose::STEP_UP)->isVerified());
    }

    /**
     * Name both gateways before any provider registers, as a published
     * configuration file holds them.
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
     * The application offers SMS and email factors, as well as TOTP.
     *
     * @return list<string>
     */
    #[\Override]
    protected function mfaTypes(): array
    {
        return ['totp', 'sms', 'email'];
    }

    /**
     * Register a recording driver of the application's own for the type,
     * stating the kind given, and send and check a step-up code for a factor of
     * that type: the driver delivers the code once, and nothing reaches
     * `laravel-authentication` or either gateway. Return how deep in a
     * transaction the driver delivered.
     *
     * @param  string  $type
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  ?string  $destination
     * @return int
     *
     * @throws \Throwable
     */
    private function assertTheDriverDeliversItsCodes(string $type, ChannelKind $kind, ?string $destination = null): int
    {
        $depth  = null;
        $driver = new RecordingCodeDriver($kind, static function () use (&$depth): void {
            $depth = DB::connection()->transactionLevel();
        });

        Mfa::extend($type, static fn (): RecordingCodeDriver => $driver);

        $factor = $this->deliveredFactor($this->signedInPerson(), $type, $destination);
        $sent   = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);
        self::assertCount(1, $driver->messages(), 'The application\'s driver must deliver the code.');
        $this->assertNothingReachedAuthentication();

        $message = $driver->messages()[0];

        self::assertSame($type, $message->type);
        $submission = Submission::challenge($factor->id, (string) $sent->challengeId, $message->code->reveal());

        self::assertTrue(Mfa::verify(self::servedCaller(), $submission, MfaPurpose::STEP_UP)->isVerified());

        return $depth ?? self::fail('The driver delivered nothing.');
    }

    /**
     * Nothing was issued by `laravel-authentication`, no delivery job waits,
     * and nothing reached either gateway.
     *
     * @return void
     */
    private function assertNothingReachedAuthentication(): void
    {
        self::assertSame(0, DB::table('one_time_codes')->count());
        self::assertSame(0, $this->runDeliveries(), 'No code waits for a delivery job.');
        self::assertSame([], $this->gatewayOf(Channel::SMS)->sent());
        self::assertSame([], $this->gatewayOf(Channel::EMAIL)->sent());
    }

    /**
     * What the container resolves the abstract to.
     *
     * @param  string  $abstract
     * @return mixed
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }

    /**
     * A person signed in on the guard, acting on their session.
     *
     * @return \Tests\Fixtures\Models\Person
     *
     * @throws \Throwable
     */
    private function signedInPerson(): Person
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        return $person;
    }
}
