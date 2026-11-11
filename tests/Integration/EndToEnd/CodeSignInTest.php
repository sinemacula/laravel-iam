<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\SendOneTimeCode;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * End-to-end tests of `laravel-authentication`'s one-time code sign-in by email
 * address and by phone number, with every adapter of this package's bound: the
 * code reaches the application's one-time code sender and signs the person in.
 * Everything runs on MySQL and PostgreSQL at READ COMMITTED and REPEATABLE
 * READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class CodeSignInTest extends TestCase
{
    use MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The person's phone number, in its normal form. */
    private const string PHONE = '+447700900789';

    /** @var string The person's email address, in its normal form. */
    private const string ADDRESS = 'ada.sign-in@example.test';

    /** @var ?\SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender The application's sender. */
    private ?FakeOneTimeCodeSender $sender = null;

    /**
     * Hold `laravel-authentication`'s delivery jobs until the test runs them.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('queue.default', 'deliveries');
        config()->set('queue.connections.deliveries', ['driver' => 'database']);

        Queue::fake();
    }

    /**
     * Rows of `[isolation level, method, identifier type, identifier as given,
     * identifier in its normal form]` for each code sign-in method at each
     * level.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: string, 4: string}>
     */
    public static function provideCodeSignIns(): iterable
    {
        foreach (self::provideIsolationLevels() as $name => [$level]) {
            yield $name . ', email' => [$level, 'email_code', 'email', 'Ada.Sign-In@Example.test', self::ADDRESS];

            yield $name . ', phone' => [$level, 'phone_code', 'phone', self::PHONE, self::PHONE];
        }
    }

    /**
     * A sign-in code reaches the application's sender once its delivery job
     * runs, to the identifier in its normal form, and signs the person in.
     *
     * @param  string  $level
     * @param  string  $method
     * @param  string  $type
     * @param  string  $given
     * @param  string  $destination
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCodeSignIns')]
    public function testACodeSignInReachesTheApplicationsSender(string $level, string $method, string $type, string $given, string $destination): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->person();
        $sender  = $this->sender ?? self::fail('No sender is bound.');
        $request = $this->codes()->send($method, [$type => $given], self::client());

        self::assertTrue($request->isSent(), $request->status->value);
        self::assertSame(0, $sender->count(), 'The code is delivered once it has committed, by the queued job.');

        foreach (Queue::pushed(SendOneTimeCode::class) as $job) {
            self::assertInstanceOf(SendOneTimeCode::class, $job);
            $job->handle($this->app ?? self::fail('The application has not booted.'));
        }

        $message = $sender->sent()[0] ?? self::fail('No code was delivered.');

        self::assertSame(1, $sender->count());
        self::assertSame(CodePurpose::SIGN_IN, $message->purpose);
        self::assertSame($type, $message->type);
        self::assertSame($destination, $message->identifier);
        self::assertSame(self::GUARD, $message->guard);
        self::assertIsThePerson($person, $message->identity);

        $result = $this->signInWith($method, $type, $given, (string) $request->challengeId, $message->code->reveal());

        self::assertTrue($result->isSignedIn(), (string) $result->reason?->value);
        self::assertNotNull($result->session);
        self::assertTrue($person->sessions()->whereKey($result->session->record->getKey())->exists(), 'The session is the person\'s.');
    }

    /**
     * Allow both code sign-in methods on the guard, beside the password.
     *
     * @return list<string>
     */
    #[\Override]
    protected function signInMethods(): array
    {
        return ['password', 'email_code', 'phone_code'];
    }

    /**
     * Bind the application's sender before the application boots.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->sender = FakeOneTimeCodeSender::fake($app);
    }

    /**
     * A person whose email address and phone number are both verified, so
     * either signs them in by code.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    private function person(): Person
    {
        $person = $this->createPerson(self::ADDRESS);

        $person->forceFill([
            'phone'             => self::PHONE,
            'email_verified_at' => CarbonImmutable::now(),
            'phone_verified_at' => CarbonImmutable::now(),
        ])->save();

        return $person;
    }

    /**
     * Sign in with the code sent for the challenge.
     *
     * @param  string  $method
     * @param  string  $type
     * @param  string  $identifier
     * @param  string  $challenge
     * @param  string  $code
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInWith(string $method, string $type, string $identifier, string $challenge, #[\SensitiveParameter] string $code): SignInResult
    {
        return $this->sessions()->signIn($method, [$type => $identifier, 'challenge' => $challenge, 'code' => $code], new SignInContext(self::client()));
    }

    /**
     * `laravel-authentication`'s code service for the guard.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\CodeService
     */
    private function codes(): CodeService
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        return $auth->codes(self::GUARD);
    }
}
