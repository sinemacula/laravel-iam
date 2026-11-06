<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Delivery\DeliverySeams;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;
use SineMacula\Laravel\Iam\Mfa\ChallengeGatewayAdapter;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\DeliversThroughGateways;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Codes\Concerns\ArrangesDeliveredFactors;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for an MFA sender of the application's own, with both
 * gateways named (IAM-3.13, IAM-8.4): whether the application binds its SMS
 * sender before any provider registers or once every provider has registered,
 * where an application provider's `register()` binds, and whatever order the
 * providers register in, every MFA code of that channel reaches the
 * application's sender, inside MFA's transaction, and verifies, while the other
 * channel's codes go through `laravel-authentication` to its gateway alike.
 * They run on every database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeGatewayAdapter::class)]
#[CoversClass(MfaSeams::class)]
#[CoversClass(DeliverySeams::class)]
final class ApplicationMfaSenderTest extends TestCase
{
    use ArrangesDeliveredFactors, DeliversThroughGateways, MigratesMembers, PermutesProviderOrder, SignsInPeople;

    /**
     * Rows of `[providers, whether the sender is bound before any provider
     * registers]`: each provider order, with the sender bound first, then last.
     *
     * @return iterable<string, array{0: list<class-string<\Illuminate\Support\ServiceProvider>>, 1: bool}>
     */
    public static function provideSenderBindings(): iterable
    {
        foreach (self::provideProviderOrders() as $name => [$providers]) {
            yield $name . ', bound before' => [$providers, true];

            yield $name . ', bound once every provider has registered' => [$providers, false];
        }
    }

    /**
     * The application's SMS sender receives every MFA SMS code, which verifies,
     * and nothing of it reaches `laravel-authentication` or the SMS gateway,
     * however it was bound; an email factor's code still goes through
     * `laravel-authentication` to the email gateway.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @param  bool  $before
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSenderBindings')]
    public function testAnApplicationsSenderReceivesItsChannelsCodesWheneverItIsBound(array $providers, bool $before): void
    {
        $own      = new FakeSmsSender;
        $bindings = [SmsSender::class => $own];

        $before ? $this->bootInOrder($providers, before: $bindings) : $this->bootInOrder($providers, after: $bindings);

        $this->queueDeliveries();

        $person = $this->signedInPerson();
        $sms    = $this->deliveredFactor($person);
        $sent   = Mfa::sendCode(self::servedCaller(), $sms->id, MfaPurpose::STEP_UP);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);
        self::assertCount(1, $own->sent(), 'The application\'s sender must receive the code.');
        self::assertSame(0, DB::table('one_time_codes')->count());
        self::assertSame(0, $this->runDeliveries(), 'No SMS code waits for a delivery job.');
        self::assertSame([], $this->gatewayOf(Channel::SMS)->sent());

        $code = $own->lastCodeTo(self::DELIVERED_PHONE) ?? self::fail('No code reached the application\'s sender.');

        self::assertTrue(Mfa::verify(self::servedCaller(), Submission::challenge($sms->id, (string) $sent->challengeId, $code), MfaPurpose::STEP_UP)->isVerified());

        $email = $this->deliveredFactor($person, 'email');

        self::assertTrue(Mfa::sendCode(self::servedCaller(), $email->id, MfaPurpose::STEP_UP)->wasSent());
        self::assertSame([], $this->gatewayOf(Channel::EMAIL)->sent());
        self::assertSame(1, $this->runDeliveries(), 'The email code waits for its delivery job.');
        self::assertSame(Source::AUTHENTICATION, ($this->gatewayOf(Channel::EMAIL)->sent()[0] ?? self::fail('No email code arrived.'))->source);
        self::assertCount(1, $own->sent());
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
