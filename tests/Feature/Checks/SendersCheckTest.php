<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Iam\Checks\SendersCheck;
use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\OneTimeCodeSenderAdapter;
use SineMacula\Laravel\Iam\Delivery\SmsSenderAdapter;
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;
use SineMacula\Laravel\Iam\Testing\FakeSmsGateway;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use Tests\Concerns\RunsChecks;
use Tests\TestCase;

/**
 * Feature tests for the check that the code senders have a gateway while a code
 * method is allowed (IAM-10.2, IAM-3.13): the routes, each named gateway, and a
 * gateway for every channel `laravel-authentication`'s sign-in codes or MFA's
 * factor codes go out on through this package.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SendersCheck::class)]
final class SendersCheckTest extends TestCase
{
    use RunsChecks;

    /**
     * With no code method allowed and no code factor enabled, nothing needs a
     * gateway, and the check passes.
     *
     * @return void
     */
    public function testNothingSendingNeedsNoGateway(): void
    {
        self::assertSame([], self::problems($this->check()->checks()));
        self::assertTrue($this->check()->applies());
        self::assertSame('senders', $this->check()->subject());
    }

    /**
     * Routes that are no map, or that name no channel, are refused; with no
     * routes configured, the shipped ones are read.
     *
     * @return void
     */
    public function testTheRoutesMustNameChannels(): void
    {
        $config = $this->app?->make('config');

        $config?->set('iam.delivery.types', null);

        self::assertSame([], self::problems($this->check()->checks()));

        $config?->set('iam.delivery.types', 'email');

        self::assertSame(['`iam.delivery.types` must map identifier types to channels.'], self::problems($this->check()->checks()));

        $config?->set('iam.delivery.types', ['email' => 'pigeon', 'phone' => 'sms']);

        self::assertSame(['`iam.delivery.types.email` must name a channel: email or sms.'], self::problems($this->check()->checks()));

        $config?->set('iam.delivery.types', ['phone' => 7]);

        self::assertSame(['`iam.delivery.types.phone` must name a channel: email or sms.'], self::problems($this->check()->checks()));
    }

    /**
     * A gateway named that is no class implementing the channel's contract is
     * refused, unless the application binds a gateway of its own.
     *
     * @return void
     */
    public function testANamedGatewayMustImplementTheContract(): void
    {
        $config = $this->app?->make('config');

        $config?->set('iam.delivery.email', FakeSmsGateway::class);
        $config?->set('iam.delivery.sms', FakeSmsGateway::class);

        self::assertSame(['`iam.delivery.email` must name a class implementing ' . EmailGateway::class . '.'], self::problems($this->check()->checks()));

        $this->app?->bind(EmailGateway::class, FakeEmailGateway::class);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * A guard allowing a code sign-in method sends on the channel its type is
     * routed to, which needs a gateway while `laravel-authentication`'s sender
     * is unbound or this package's; a gateway bound or named passes.
     *
     * @return void
     */
    public function testACodeMethodNeedsAGatewayOnItsChannel(): void
    {
        $config = $this->app?->make('config');

        $config?->set('auth.guards.api.application.methods', ['password', 'email_code', 'phone_code']);

        self::assertSame([
            'Guards [api] send on email with no gateway: name one in `iam.delivery.email`, or bind ' . EmailGateway::class . '.',
            'Guards [api] send on sms with no gateway: name one in `iam.delivery.sms`, or bind ' . SmsGateway::class . '.',
        ], self::problems($this->check()->checks()));

        $config?->set('iam.delivery.types', ['email' => 'sms', 'phone' => 'sms']);
        $config?->set('iam.delivery.sms', FakeSmsGateway::class);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * A guard allowing a code sign-in method whose identifier type the routes
     * leave out is refused, whatever gateways are named, since no code of that
     * type can be delivered; each method is refused once, naming every guard
     * allowing it, and a sender the application bound itself is left alone.
     *
     * @return void
     */
    public function testACodeMethodWhoseTypeIsUnroutedIsRefused(): void
    {
        $app = $this->app;

        assert($app !== null);

        $config = $app->make('config');
        $guards = $config->get('auth.guards');

        assert(is_array($guards) && is_array($guards['api']));

        $config->set('auth.guards.portal', [...$guards['api'], 'application' => ['methods' => ['phone_code']]]);
        $config->set('auth.guards.api.application.methods', ['password', 'phone_code']);
        $config->set('iam.delivery.types', ['email' => 'email']);
        $config->set('iam.delivery.email', FakeEmailGateway::class);

        $app->bind(OneTimeCodeSender::class, OneTimeCodeSenderAdapter::class);

        $phone = 'Guards [api, portal] allow `phone_code`, but `iam.delivery.types` routes no `phone` type to a channel.';

        self::assertSame([$phone], self::problems($this->check()->checks()));

        $config->set('auth.guards.api.application.methods', ['email_code', 'phone_code']);
        $config->set('iam.delivery.types', []);

        self::assertSame([
            'Guards [api] allow `email_code`, but `iam.delivery.types` routes no `email` type to a channel.',
            $phone,
        ], self::problems($this->check()->checks()));

        $config->set('iam.delivery.types', 'email');

        self::assertSame(['`iam.delivery.types` must map identifier types to channels.'], self::problems($this->check()->checks()));

        $config->set('iam.delivery.types', ['email' => 'email']);
        $config->set('auth.guards.portal.application.methods', ['password']);
        $config->set('auth.guards.api.application.methods', ['password', 'email_code']);

        self::assertSame([], self::problems($this->check()->checks()));

        $config->set('auth.guards.api.application.methods', ['phone_code']);
        $app->bind(OneTimeCodeSender::class, static fn (): ?object => null);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * Every guard allowing a code method routed to a channel is named once,
     * whichever method it allows, after any guard of another driver, one the
     * policy cannot answer for or one allowing no code method, a guard named by
     * a number included; and this package's own sender, bound with no gateway,
     * needs one.
     *
     * @return void
     */
    public function testEveryGuardSendingOnAChannelIsNamedOnce(): void
    {
        $app = $this->app;

        assert($app !== null);

        $config = $app->make('config');
        $guards = $config->get('auth.guards');

        assert(is_array($guards) && is_array($guards['api']));

        $config->set('auth.guards', [
            'web'       => ['driver' => 'session', 'provider' => 'people'],
            'malformed' => [...$guards['api'], 'application' => 'not a block'],
            'password'  => [...$guards['api'], 'application' => ['methods' => ['password']]],
            'api'       => [...$guards['api'], 'application' => ['methods' => ['email_code', 'phone_code']]],
            'portal'    => [...$guards['api'], 'application' => ['methods' => ['email_code']]],
            7           => [...$guards['api'], 'application' => ['methods' => ['email_code']]],
            'admin'     => [...$guards['api'], 'application' => ['methods' => ['phone_code']]],
        ]);
        $config->set('iam.delivery.types', ['email' => 'sms', 'phone' => 'sms']);

        $app->bind(OneTimeCodeSender::class, OneTimeCodeSenderAdapter::class);

        $problem = 'Guards [api, portal, 7, admin] send on sms with no gateway: name one in `iam.delivery.sms`, or bind ' . SmsGateway::class . '.';

        self::assertSame([$problem], self::problems($this->check()->checks()));
    }

    /**
     * A sender the application bound itself needs no gateway of this package's.
     *
     * @return void
     */
    public function testTheApplicationsOwnSenderNeedsNoGateway(): void
    {
        $this->app?->make('config')->set('auth.guards.api.application.methods', ['email_code']);
        $this->app?->bind(OneTimeCodeSender::class, static fn (): ?object => null);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * Only `jwt` guards the application policy can answer for are read: a guard
     * of another driver, one that is no array and one whose policy throws are
     * left, the last to `authentication:check`.
     *
     * @return void
     */
    public function testOnlyGuardsThePolicyAnswersForAreRead(): void
    {
        $config = $this->app?->make('config');

        $config?->set('auth.guards.web', ['driver' => 'session', 'application' => ['methods' => ['email_code']]]);
        $config?->set('auth.guards.broken', 'not a guard');
        $config?->set('auth.guards.malformed', ['driver' => 'jwt', 'application' => 'not a block']);

        self::assertSame([], self::problems($this->check()->checks()));

        $config?->set('auth.guards', null);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * An MFA application enabling a code factor sends on its channel, which
     * needs a gateway while MFA's sender of that channel is its null default,
     * this package's or unbound; MFA's sender bound by the application needs
     * none, and this package's, bound with no gateway, needs one again.
     *
     * @return void
     */
    public function testACodeFactorNeedsAGatewayOnItsChannel(): void
    {
        $app = $this->app;

        assert($app !== null);

        $config = $app->make('config');

        $applications = $config->get('mfa.applications');

        assert(is_array($applications) && is_array($applications['api']));

        $config->set('mfa.applications', [
            'admin'  => 'not an application',
            'portal' => ['types' => 'sms'],
            'api'    => [...$applications['api'], 'types' => ['totp', 'sms', 'email']],
        ]);

        self::assertSame([
            'MFA applications [api] send on email with no gateway: name one in `iam.delivery.email`, or bind ' . EmailGateway::class . '.',
            'MFA applications [api] send on sms with no gateway: name one in `iam.delivery.sms`, or bind ' . SmsGateway::class . '.',
        ], self::problems($this->check()->checks()));

        $app->bind(SmsSender::class, static fn (): ?object => null);
        $app->offsetUnset(EmailSender::class);
        $app->bind(EmailGateway::class, FakeEmailGateway::class);

        self::assertSame([], self::problems($this->check()->checks()));

        $app->bind(SmsSender::class, SmsSenderAdapter::class);

        self::assertSame([
            'MFA applications [api] send on sms with no gateway: name one in `iam.delivery.sms`, or bind ' . SmsGateway::class . '.',
        ], self::problems($this->check()->checks()));

        $config->set('mfa.applications', null);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * The check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\SendersCheck
     */
    private function check(): SendersCheck
    {
        $check = $this->app?->make(SendersCheck::class);

        assert($check instanceof SendersCheck);

        return $check;
    }
}
