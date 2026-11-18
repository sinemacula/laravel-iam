<?php

declare(strict_types = 1);

namespace Tests\Integration\Audit;

use Illuminate\Http\Request;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\Iam\Audit\Correlation;
use SineMacula\Laravel\Iam\Audit\Mappers\AuthenticationEventMapper;
use SineMacula\Laravel\Iam\Audit\Mappers\MfaEventMapper;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Codes\Concerns\ArrangesDeliveredFactors;
use Tests\Fixtures\Mfa\Codes\Concerns\DeliversFactorCodes;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Contract test for the record sequence of a sign-in that waits on MFA.
 *
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationEventMapper::class)]
#[CoversClass(MfaEventMapper::class)]
#[WithConfig('audit-log.capture.laravel.except_guards', [self::GUARD])]
#[WithConfig('audit-log.definitions.require_registered', true)]
final class PendingSignInSequenceTest extends TestCase
{
    use ArrangesDeliveredFactors, DeliversFactorCodes, MigratesMembers, SignsInPeople;

    /** @var list<string> The client every record names. */
    private const array CLIENT = [self::CLIENT_IP, self::CLIENT_AGENT];

    /**
     * Fake the delivery of factor codes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fakeFactorCodeDelivery();
    }

    /**
     * A pending sign-in completed with a delivered code after a wrong one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInCompletedWithADeliveredCode(): void
    {
        $expiry = $this->freezeSecond()->addSeconds(300)->toJSON();
        $person = $this->createPerson();
        $factor = $this->deliveredFactor($person);
        $fake   = AuditLog::fake();
        $result = $this->attemptSignIn($person);

        self::assertTrue($result->isPending(), (string) $result->reason?->value);
        self::assertNotNull($result->credential);

        $client = ['REMOTE_ADDR' => self::CLIENT_IP, 'HTTP_USER_AGENT' => self::CLIENT_AGENT];
        $caller = self::servedCaller(Request::create('/mfa/verify', 'POST', ['pending_credential' => $result->credential->reveal()], server: $client));
        $sent   = Mfa::sendCode($caller, $factor->id, Purpose::SIGN_IN);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);

        $code = $this->deliveredCodeTo(self::DELIVERED_PHONE);

        self::assertFalse(Mfa::verify($caller, Submission::challenge($factor->id, (string) $sent->challengeId, self::wrong($code)), Purpose::SIGN_IN)->isVerified());
        self::assertTrue(Mfa::verify($caller, Submission::challenge($factor->id, (string) $sent->challengeId, $code), Purpose::SIGN_IN)->isVerified());

        $session   = $person->sessions()->sole()->getKey();
        $challenge = Correlation::mfaChallenge($sent->challengeId);

        self::assertIsString($session);
        self::assertNotNull($challenge);

        $person  = [Person::class, (string) $person->id];
        $own     = ['success', null, $person, $person, $person, $session];
        $refused = [null, $person, null, $session, $challenge, self::CLIENT];
        $mfa     = ['application' => self::GUARD, 'purpose' => 'sign_in', 'factor_id' => $factor->id, 'factor_type' => 'sms'];

        self::assertSame([
            ['session.pending', ...$own, Correlation::session($session), self::CLIENT, ['method' => 'password', 'requires' => ['mfa'], 'expires_at' => $expiry]],
            ['mfa.code_sent', ...$own, $challenge, self::CLIENT, $mfa],
            ['authentication.factor_code_failed', 'failure', 'invalid_credentials', ...$refused, null],
            ['mfa.verification_failed', 'failure', 'invalid_code', null, $person, $person, $session, $challenge, self::CLIENT, [...$mfa, 'type' => 'sms']],
            ['session.created', ...$own, Correlation::session($session), self::CLIENT, ['method' => 'password']],
            ['authentication.signed_in', ...$own, Correlation::session($session), self::CLIENT, null],
            ['mfa.verification_passed', ...$own, $challenge, self::CLIENT, [...$mfa, 'type' => 'sms']],
        ], array_map(static fn (AuditRecord $record): array => [
            $record->event,
            $record->outcome,
            $record->reason,
            self::pair($record->actorType, $record->actorId),
            self::pair($record->subjectType, $record->subjectId),
            self::pair($record->principalType, $record->principalId),
            $record->sessionId,
            $record->correlationId,
            [$record->ip, $record->userAgent],
            $record->properties,
        ], $fake->recorded()));
    }

    /**
     * Bind the fake one-time code sender.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->defineFactorCodes($app);
    }

    /**
     * A reference's type and id, or `null` for none.
     *
     * @param  ?string  $type
     * @param  ?string  $id
     * @return ?list<string>
     */
    private static function pair(?string $type, ?string $id): ?array
    {
        return $type === null || $id === null ? null : [$type, $id];
    }

    /**
     * A code of the same length that is not the code.
     *
     * @param  string  $code
     * @return string
     */
    private static function wrong(#[\SensitiveParameter] string $code): string
    {
        $zeros = str_repeat('0', strlen($code));

        return $code === $zeros ? str_repeat('1', strlen($code)) : $zeros;
    }
}
