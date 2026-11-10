<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Auth\GenericUser;
use Illuminate\Log\Logger;
use Illuminate\Support\Facades\Log;
use Monolog\Handler\TestHandler;
use Monolog\Logger as Monolog;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use Tests\TestCase;

/**
 * Feature tests for a code message logged by accident, as a gateway might log
 * what it was given: MFA's log redaction, which every log channel runs, logs it
 * by its public properties with the code redacted, never the destination or the
 * recipient, and the log is written rather than failing the delivery.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeMessage::class)]
final class CodeMessageLoggingTest extends TestCase
{
    /** @var string The log channel the test records. */
    private const string CHANNEL = 'recorded';

    /** @var string The code the message carries. */
    private const string CODE = '493027';

    /** @var string The address the message goes to. */
    private const string ADDRESS = 'ada.logged@example.test';

    /**
     * A logged message is written with its code redacted, and neither its code,
     * its address nor its recipient appears anywhere in the record.
     *
     * @return void
     */
    public function testALoggedMessageIsWrittenWithItsCodeRedacted(): void
    {
        $message = new CodeMessage(
            self::GUARD,
            CodePurpose::SIGN_IN,
            Channel::EMAIL,
            'email',
            self::ADDRESS,
            new Secret(self::CODE),
            CarbonImmutable::now()->addMinutes(10),
            new GenericUser(['id' => 'person-logged', 'email' => self::ADDRESS]),
        );

        Log::channel(self::CHANNEL)->info('Delivering a code.', ['message' => $message]);

        $records = $this->handler()->getRecords();

        self::assertCount(1, $records);

        $context = $records[0]->context['message'] ?? null;

        self::assertIsArray($context);
        self::assertArrayHasKey(CodeMessage::class, $context);

        $logged = $context[CodeMessage::class];

        self::assertIsArray($logged);
        self::assertSame(Secret::REDACTED, $logged['code']);
        self::assertSame(self::GUARD, $logged['application']);
        self::assertArrayNotHasKey('destination', $logged);
        self::assertArrayNotHasKey('recipient', $logged);

        $formatted = $records[0]->formatted;

        self::assertIsString($formatted);

        $written = print_r($records[0]->toArray(), true) . $formatted;

        self::assertStringNotContainsString(self::CODE, $written);
        self::assertStringNotContainsString(self::ADDRESS, $written);
        self::assertStringNotContainsString('person-logged', $written);
    }

    /**
     * Record a log channel the test writes to, configured before MFA boots so
     * its log redaction is tapped onto it, as onto every configured channel.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $app->make('config')->set('logging.channels.' . self::CHANNEL, ['driver' => 'monolog', 'handler' => TestHandler::class]);
    }

    /**
     * The handler that recorded the channel's log.
     *
     * @return \Monolog\Handler\TestHandler
     */
    private function handler(): TestHandler
    {
        $channel = Log::channel(self::CHANNEL);

        self::assertInstanceOf(Logger::class, $channel);

        $logger = $channel->getLogger();

        self::assertInstanceOf(Monolog::class, $logger);

        $handler = $logger->getHandlers()[0] ?? null;

        self::assertInstanceOf(TestHandler::class, $handler);

        return $handler;
    }
}
