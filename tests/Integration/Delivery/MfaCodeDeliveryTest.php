<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;
use SineMacula\Laravel\Iam\Delivery\DeliverySettings;
use SineMacula\Laravel\Iam\Delivery\EmailSenderAdapter;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;
use SineMacula\Laravel\Iam\Delivery\SmsSenderAdapter;
use SineMacula\Laravel\Iam\Exceptions\DeliveryNotConfiguredException;
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;
use SineMacula\Laravel\Iam\Testing\FakeSmsGateway;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Exceptions\CodeDeliveryFailedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Delivery\ScriptedGateway;
use Tests\Fixtures\Mfa\Codes\Concerns\ArrangesDeliveredFactors;
use Tests\TestCase;

/**
 * Integration tests for MFA's own codes delivered through the application's
 * gateways (IAM-3.13), with MFA's own challenge gateway bound as the
 * application's, so MFA draws, keeps and sends its codes itself, through its
 * SMS and email senders, which this package points at the gateways named in
 * `iam.delivery`.
 *
 * Each code reaches the gateway of its factor's channel as this package's one
 * message and verifies. The gateway runs synchronously inside MFA's
 * transaction, after the identity's state and its factors are locked and the
 * code is written, and the delivery takes no lock of its own, so a gateway that
 * throws, or one the adapter cannot resolve, rolls the code back: nothing is
 * kept, and the next send goes ahead as if none had been made. They run on
 * MySQL and PostgreSQL at READ COMMITTED and REPEATABLE READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SmsSenderAdapter::class)]
#[CoversClass(EmailSenderAdapter::class)]
#[CoversClass(DeliverySettings::class)]
final class MfaCodeDeliveryTest extends TestCase
{
    use ArrangesDeliveredFactors, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /**
     * The members' senders are this package's adapters, pointed at the gateways
     * the application names.
     *
     * @return void
     */
    public function testMfasSendersArePointedAtTheGateways(): void
    {
        self::assertSame(SmsSenderAdapter::class, $this->resolved(SmsSender::class));
        self::assertSame(EmailSenderAdapter::class, $this->resolved(EmailSender::class));
    }

    /**
     * Rows of `[isolation level, factor type]`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideDeliveries(): iterable
    {
        foreach (self::provideIsolationLevels() as $name => [$level]) {
            yield $name . ', sms' => [$level, 'sms'];

            yield $name . ', email' => [$level, 'email'];
        }
    }

    /**
     * A code MFA sends reaches the gateway of its factor's channel, once, as
     * this package's message, and verifies.
     *
     * @param  string  $level
     * @param  string  $type
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeliveries')]
    public function testACodeReachesTheGatewayOfItsChannelAndVerifies(string $level, string $type): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$gateway, $other] = $this->fakes($type);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $factor      = $this->deliveredFactor($person, $type);
        $destination = self::deliveredDestination($person, $type);
        $sent        = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);

        self::assertIsString($sent->challengeId);
        self::assertSame([], $other->sent());
        self::assertCount(1, $gateway->sent());

        $message = $gateway->sent()[0];

        self::assertSame(self::GUARD, $message->application);
        self::assertSame(MfaPurpose::STEP_UP, $message->memberPurpose);
        self::assertSame(Purpose::ADDITIONAL_FACTOR, $message->purpose);
        self::assertSame(Source::MFA, $message->source);
        self::assertSame(Channel::from($type), $message->channel);
        self::assertSame($type, $message->type);
        self::assertSame($destination, $message->destination());
        self::assertSame($sent->expiresAt?->getTimestamp(), $message->expiresAt->getTimestamp());
        self::assertIsThePerson($person, $message->recipient());
        self::assertSame($factor->id, $message->factor?->id);
        self::assertNotSame($destination, $message->factor->maskedDestination);

        $code = $gateway->lastCodeTo($destination, Purpose::ADDITIONAL_FACTOR);

        self::assertIsString($code);
        self::assertTrue(Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, $sent->challengeId, $code), MfaPurpose::STEP_UP)->isVerified());
    }

    /**
     * A gateway that throws rolls the code back: MFA reports the delivery
     * failed, keeps no code, and the next send goes ahead, as if none had been
     * made.
     *
     * @param  string  $level
     * @param  string  $type
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeliveries')]
    public function testAGatewayThatThrowsRollsTheCodeBack(string $level, string $type): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        [$gateway] = $this->fakes($type);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $factor = $this->deliveredFactor($person, $type);

        $gateway->failNext(new \RuntimeException('The provider refused the message.'));

        $this->assertDeliveryFails(static fn () => Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP), \RuntimeException::class);

        self::assertSame(0, $this->codesOf($factor));
        self::assertSame([], $gateway->sent());

        $sent = Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP);

        self::assertNull($sent->reason);
        self::assertSame(1, $this->codesOf($factor));
        self::assertCount(1, $gateway->sent());
    }

    /**
     * A gateway the adapter cannot resolve, one named by a class that is no
     * gateway, rolls the code back as a gateway's failure does.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAGatewayTheAdapterCannotResolveRollsTheCodeBack(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        config()->set('iam.delivery.sms', \stdClass::class);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $factor = $this->deliveredFactor($person);

        $this->assertDeliveryFails(static fn () => Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP), DeliveryNotConfiguredException::class);

        self::assertSame(0, $this->codesOf($factor));
    }

    /**
     * The gateway runs inside MFA's transaction, once the identity's state and
     * its factors are locked and the code is written, and nothing from the
     * code's write to the gateway takes a lock: the delivery adds none to MFA's
     * order.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testTheGatewayRunsInsideMfasTransactionAndTakesNoLock(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $factor     = $this->deliveredFactor($person);
        $statements = [];
        $observed   = null;

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = strtolower($query->sql);
        });

        $this->app?->instance(SmsGateway::class, new ScriptedGateway(function (CodeMessage $message, ScriptedGateway $gateway) use (&$statements, &$observed, $factor): void {
            $observed = [$statements, DB::connection()->transactionLevel(), $this->codesOf($factor)];

            $gateway->deliver($message);
        }));

        self::assertNull(Mfa::sendCode(self::servedCaller(), $factor->id, MfaPurpose::STEP_UP)->reason);
        self::assertIsArray($observed);

        [$before, $depth, $codes] = $observed;

        $write   = self::lastIndexOf($before, 'insert into ' . self::quoted('mfa_codes'));
        $factors = self::lastIndexOf(array_slice($before, 0, $write), self::quoted('mfa_factors'), 'for update');
        $state   = self::lastIndexOf(array_slice($before, 0, $factors), self::quoted('mfa_identity_states'), 'for update');

        self::assertGreaterThan(0, $depth, 'The gateway must run inside MFA\'s transaction.');
        self::assertSame(1, $codes, 'The code must be written before the gateway runs.');
        self::assertLessThan($factors, $state, 'The identity\'s state must be locked, then its factors, before the code is written.');
        self::assertSame([], array_filter(array_slice($before, $write + 1), static fn (string $sql): bool => str_contains($sql, 'for update') || str_contains($sql, 'for share')));
    }

    /**
     * Name a fake of each gateway before any provider registers, as a published
     * configuration file holds them, so MFA's senders are pointed at the
     * gateways and MFA boots while it offers `sms` and `email` factors.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $app->make('config')->set('iam.delivery', [
            'email' => FakeEmailGateway::class,
            'sms'   => FakeSmsGateway::class,
            'types' => ['email' => 'email', 'phone' => 'sms'],
        ]);
    }

    /**
     * Bind MFA's own challenge gateway as the application's, so MFA draws,
     * keeps and sends its codes itself, through its senders.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $app->bind(ChallengeGateway::class, PackageChallengeGateway::class);
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
     * Bind a fake of each gateway, and return the one of the type's channel,
     * then the other.
     *
     * @param  string  $type
     * @return list<\SineMacula\Laravel\Iam\Testing\FakeEmailGateway|\SineMacula\Laravel\Iam\Testing\FakeSmsGateway>
     */
    private function fakes(string $type): array
    {
        $sms   = FakeSmsGateway::fake($this->app);
        $email = FakeEmailGateway::fake($this->app);

        return $type === 'sms' ? [$sms, $email] : [$email, $sms];
    }

    /**
     * Run the send, failing unless MFA reports the delivery failed, caused by
     * an exception of the class given.
     *
     * @param  \Closure(): mixed  $send
     * @param  class-string<\Throwable>  $cause
     * @return void
     */
    private function assertDeliveryFails(\Closure $send, string $cause): void
    {
        try {
            $send();
        } catch (CodeDeliveryFailedException $exception) {
            self::assertInstanceOf($cause, $exception->getPrevious());

            return;
        }

        self::fail('MFA must report the delivery failed.');
    }

    /**
     * The class the container resolves the abstract to.
     *
     * @param  string  $abstract
     * @return string
     */
    private function resolved(string $abstract): string
    {
        $instance = $this->app?->make($abstract);

        self::assertIsObject($instance);

        return $instance::class;
    }

    /**
     * How many codes MFA keeps for the factor, read on the storage connection.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return int
     */
    private function codesOf(Factor $factor): int
    {
        return DB::table('mfa_codes')->where('factor_id', $factor->id)->count();
    }

    /**
     * The index of the last statement that holds every text given, failing the
     * test when none does.
     *
     * @param  list<string>  $statements
     * @param  string  ...$texts
     * @return int
     */
    private static function lastIndexOf(array $statements, string ...$texts): int
    {
        foreach (array_reverse($statements, true) as $index => $sql) {
            if (array_filter($texts, static fn (string $text): bool => !str_contains($sql, $text)) === []) {
                return $index;
            }
        }

        self::fail(sprintf('No statement holds [%s].', implode('], [', $texts)));
    }

    /**
     * The table or column name, quoted as the storage connection's grammar
     * quotes it.
     *
     * @param  string  $name
     * @return string
     */
    private static function quoted(string $name): string
    {
        return DB::connection()->getDriverName() === 'mysql' ? '`' . $name . '`' : '"' . $name . '"';
    }
}
