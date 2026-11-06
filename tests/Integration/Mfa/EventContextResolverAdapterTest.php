<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Iam\Mfa\EventContextResolverAdapter;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Events\FactorsReset;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\EventContextResolverTests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\TestCase;

/**
 * Integration tests for MFA's event context filled from
 * `laravel-authentication`'s caller (IAM-3.12): an event about the identity the
 * guard serves carries its principal, the tenant its validated session records
 * and the session MFA names its sign-in by, beside the identity, the
 * application and the request's IP address and user agent; an event about
 * anyone else, or about no identity, carries none of the sign-in; no tenant set
 * on the guard beside the session is ever carried; it never throws for want of
 * a request or a guard that holds sessions; and MFA's own events carry it once
 * it is bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContextResolverAdapter::class)]
final class EventContextResolverAdapterTest extends TestCase
{
    use EventContextResolverTests, MigratesMembers, SignsInPeople;

    /** @var string The tenant the tests' sessions act in. */
    private const string TENANT = 'tenant-01J9Z3';

    /** @var string The alias an application's morph map gives people. */
    private const string MORPH = 'person';

    /** @var string The IP address the tests' requests come from. */
    private const string IP = '192.0.2.10';

    /** @var string The user agent the tests' requests come from. */
    private const string USER_AGENT = 'IamTest/1.0';

    /**
     * An event about the identity the guard serves carries its sign-in: its
     * principal, its session's tenant and the session, beside the identity, the
     * application and the request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEventAboutTheServedIdentityCarriesItsSignIn(): void
    {
        $person  = $this->createPerson();
        $session = $this->actInTenant($person);

        self::assertSame($this->signInContext($person, $session), $this->adapter()->resolve($person, $this->request()));
    }

    /**
     * The identity and the principal are carried by their morph class, so an
     * application's morph map is honoured.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityAndThePrincipalAreCarriedByTheirMorphClass(): void
    {
        $person   = $this->createPerson();
        $previous = Relation::morphMap();

        $this->actInTenant($person);

        try {
            Relation::morphMap([self::MORPH => Person::class]);

            $context = $this->adapter()->resolve($person, $this->request());
        } finally {
            Relation::morphMap($previous, false);
        }

        self::assertSame(self::MORPH, $context['identity_type']);
        self::assertSame(self::MORPH, $context['principal_type']);
    }

    /**
     * Nothing of the sign-in the guard serves is attributed to an event about
     * another identity: only that identity, the application and the request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingOfAnotherIdentitysSignInIsAttributed(): void
    {
        $person = $this->createPerson();

        $this->actInTenant($this->createPerson());

        self::assertSame(self::context([
            'identity_type' => $person->getMorphClass(),
            'identity_id'   => self::keyOf($person),
            'application'   => self::GUARD,
            'ip'            => self::IP,
            'user_agent'    => self::USER_AGENT,
        ]), $this->adapter()->resolve($person, $this->request()));
    }

    /**
     * An event about no identity carries no sign-in, though the guard serves
     * one: only the application and the request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEventAboutNoIdentityCarriesNoSignIn(): void
    {
        $this->actInTenant($this->createPerson());

        self::assertSame(self::context([
            'application' => self::GUARD,
            'ip'          => self::IP,
            'user_agent'  => self::USER_AGENT,
        ]), $this->adapter()->resolve(null, $this->request()));
    }

    /**
     * Without a request there is nothing to describe but the identity: no
     * application, no sign-in and no request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutARequestOnlyTheIdentityIsKnown(): void
    {
        $person = $this->createPerson();

        $this->actInTenant($person);

        self::assertSame(self::context([
            'identity_type' => $person->getMorphClass(),
            'identity_id'   => self::keyOf($person),
        ]), $this->adapter()->resolve($person, null));
    }

    /**
     * The tenant carried is the session's own: never one set on the guard
     * beside the session, so a session in no tenant carries none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoTenantSetBesideTheSessionIsCarried(): void
    {
        $person = $this->createPerson();

        $this->actInTenant($person);
        $this->actingInTenant(new ClaimedTenant('tenant-claimed'));

        self::assertSame(self::TENANT, $this->adapter()->resolve($person, $this->request())['tenant_id']);

        $this->signInAndActOnSession($person);
        $this->actingInTenant(new ClaimedTenant('tenant-claimed'));

        self::assertNull($this->adapter()->resolve($person, $this->request())['tenant_id']);
    }

    /**
     * Rows of `[default guard, application]` that hold no sessions: Laravel's
     * own session guard, a name no guard is declared under, and none.
     *
     * @return iterable<string, array{0: string, 1: ?string}>
     */
    public static function provideDefaultGuardsThatHoldNoSessions(): iterable
    {
        yield 'another kind of guard' => ['web', 'web'];

        yield 'no guard' => ['not-a-guard', 'not-a-guard'];

        yield 'none' => ['', null];

        yield 'blank' => ['  ', null];
    }

    /**
     * A default guard that holds no sessions describes no sign-in, and is never
     * refused: an event is only described.
     *
     * @param  string  $guard
     * @param  ?string  $application
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDefaultGuardsThatHoldNoSessions')]
    public function testADefaultGuardThatHoldsNoSessionsDescribesNoSignIn(string $guard, ?string $application): void
    {
        $person = $this->createPerson();

        $this->actInTenant($person);

        Config::set('auth.defaults.guard', $guard);

        self::assertSame(self::context([
            'identity_type' => $person->getMorphClass(),
            'identity_id'   => self::keyOf($person),
            'application'   => $application,
            'ip'            => self::IP,
            'user_agent'    => self::USER_AGENT,
        ]), $this->adapter()->resolve($person, $this->request()));
    }

    /**
     * Bound as MFA's event context resolver, MFA's own events carry the
     * sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfasEventsCarryIt(): void
    {
        $this->app?->bind(EventContextResolver::class, EventContextResolverAdapter::class);

        Event::fake([FactorsReset::class]);

        $person   = $this->createPerson();
        $session  = $this->actInTenant($person);
        $expected = $this->signInContext($person, $session);

        $this->request();

        Mfa::resetIdentity($person, Actor::of($person), 'Lost device');

        Event::assertDispatched(FactorsReset::class, static fn (FactorsReset $event): bool => $event->context === $expected);
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\EventContextResolver
     */
    #[\Override]
    protected function eventContextResolver(): EventContextResolver
    {
        return $this->adapter();
    }

    /**
     * An identity events are about: a person signed in on the guard.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function eventIdentity(): MultiFactorAuthenticatable
    {
        $person = $this->createPerson();

        $this->actInTenant($person);

        return $person;
    }

    /**
     * The context of an event about the person, signed in on the session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return array<string, int|string|null>
     */
    private function signInContext(Person $person, EloquentSession&Model $session): array
    {
        return self::context([
            'identity_type'  => $person->getMorphClass(),
            'identity_id'    => self::keyOf($person),
            'principal_type' => $person->getMorphClass(),
            'principal_id'   => self::keyOf($person),
            'tenant_id'      => self::TENANT,
            'application'    => self::GUARD,
            'session_id'     => $this->signInReference($session),
            'ip'             => self::IP,
            'user_agent'     => self::USER_AGENT,
        ]);
    }

    /**
     * Sign the person in, record the tenant on the new session's row as a
     * sign-in into the tenant records it, and act on the session as a bearer
     * request for it from the tests' client would.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function actInTenant(Person $person): EloquentSession&Model
    {
        $session = $this->signIn($person)->record;

        $session->forceFill([$session->getTenantIdName() => self::TENANT])->save();

        $this->actingOnSession($session, self::GUARD);

        return $session;
    }

    /**
     * A context with the values given and every other key `null`, in the order
     * MFA keeps.
     *
     * @param  array<string, ?string>  $values
     * @return array<string, int|string|null>
     */
    private static function context(array $values): array
    {
        return EventContext::allowlist($values);
    }

    /**
     * The person's key, as an event carries it.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return string
     */
    private static function keyOf(Person $person): string
    {
        return EventContext::scalarKey($person->getKey()) ?? self::fail('The person has no key.');
    }

    /**
     * The request being served, from the tests' client.
     *
     * @return \Illuminate\Http\Request
     */
    private function request(): Request
    {
        $request = $this->app?->make('request');

        self::assertInstanceOf(Request::class, $request);

        $request->server->set('REMOTE_ADDR', self::IP);
        $request->headers->set('User-Agent', self::USER_AGENT);

        return $request;
    }

    /**
     * Resolve the adapter under test from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\EventContextResolverAdapter
     */
    private function adapter(): EventContextResolverAdapter
    {
        $adapter = $this->app?->make(EventContextResolverAdapter::class);

        self::assertInstanceOf(EventContextResolverAdapter::class, $adapter);

        return $adapter;
    }
}
