<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Iam\Mfa\EventContextResolverAdapter;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Events\FactorsReset;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\EventContextResolverTests;
use Tests\Concerns\BindsStrayRequests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\TestCase;

/**
 * Integration tests for MFA's event context filled from the values MFA hands it
 * (IAM-3.12): an event carries the identity it is about and the IP address and
 * user agent of the client MFA hands it, and nothing of any sign-in the guard
 * holds, the identity's own or anyone else's, nor any tenant, since MFA hands
 * the resolver no application or sign-in to name them from; it never reads a
 * request bound in the container or the default guard, never throws, and MFA's
 * own events carry it once it is bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContextResolverAdapter::class)]
final class EventContextResolverAdapterTest extends TestCase
{
    use BindsStrayRequests, EventContextResolverTests, MigratesMembers, SignsInPeople;

    /** @var string The tenant the tests' sessions act in. */
    private const string TENANT = 'tenant-01J9Z3';

    /** @var string The alias an application's morph map gives people. */
    private const string MORPH = 'person';

    /** @var string The IP address the tests' client comes from. */
    private const string IP = '192.0.2.10';

    /** @var string The user agent the tests' client sends. */
    private const string USER_AGENT = 'IamTest/1.0';

    /**
     * An event about the identity the guard serves carries the identity and the
     * client alone: none of the sign-in the guard holds, though it is the
     * identity's own, since it may be another application's than the one the
     * operation ran on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEventAboutTheServedIdentityCarriesNoneOfItsSignIn(): void
    {
        $person = $this->createPerson();

        $this->actInTenant($person);

        self::assertSame(self::identityContext($person), $this->adapter()->resolve($person, self::served()));
    }

    /**
     * The identity is carried by its morph class, so an application's morph map
     * is honoured.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityIsCarriedByItsMorphClass(): void
    {
        $person   = $this->createPerson();
        $previous = Relation::morphMap();

        try {
            Relation::morphMap([self::MORPH => Person::class]);

            $context = $this->adapter()->resolve($person, self::served());
        } finally {
            Relation::morphMap($previous, false);
        }

        self::assertSame(self::MORPH, $context['identity_type']);
        self::assertNull($context['principal_type']);
    }

    /**
     * Nothing of the sign-in the guard serves is attributed to an event about
     * another identity: only that identity and the client.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingOfAnotherIdentitysSignInIsAttributed(): void
    {
        $person = $this->createPerson();

        $this->actInTenant($this->createPerson());

        self::assertSame(self::identityContext($person), $this->adapter()->resolve($person, self::served()));
    }

    /**
     * An event about no identity carries no sign-in, though the guard serves
     * one: only the client.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEventAboutNoIdentityCarriesOnlyTheClient(): void
    {
        $this->actInTenant($this->createPerson());

        self::assertSame(self::context([
            'ip'         => self::IP,
            'user_agent' => self::USER_AGENT,
        ]), $this->adapter()->resolve(null, self::served()));
    }

    /**
     * Served to no client, as an administrator's, a console command's or a
     * pruning's change is, there is nothing to describe but the identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAClientOnlyTheIdentityIsKnown(): void
    {
        $person = $this->createPerson();

        $this->actInTenant($person);

        self::assertSame(self::context([
            'identity_type' => $person->getMorphClass(),
            'identity_id'   => self::keyOf($person),
        ]), $this->adapter()->resolve($person, null));
    }

    /**
     * A request bound in the container never reaches the context: the client is
     * the one MFA hands, one of which nothing is known names no IP address or
     * user agent, and an event handed no client names none, though the
     * container holds a request from another client.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundRequestNeverReachesTheContext(): void
    {
        $person = $this->createPerson();

        $this->actInTenant($person);
        $this->bindStrayRequest();

        $known = self::identityContext($person);

        self::assertSame($known, $this->adapter()->resolve($person, self::served()));
        self::assertSame(array_replace($known, ['ip' => null, 'user_agent' => null]), $this->adapter()->resolve($person, ClientContext::unknown()));
        self::assertSame(self::context([
            'identity_type' => $person->getMorphClass(),
            'identity_id'   => self::keyOf($person),
        ]), $this->adapter()->resolve($person, null));
    }

    /**
     * No tenant is carried: neither the session's own nor one set on the guard
     * beside it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoTenantIsCarried(): void
    {
        $person = $this->createPerson();

        $this->actInTenant($person);
        $this->actingInTenant(new ClaimedTenant('tenant-claimed'));

        self::assertNull($this->adapter()->resolve($person, self::served())['tenant_id']);
    }

    /**
     * Rows of `[default guard]`: one that holds sessions, Laravel's own session
     * guard, a name no guard is declared under, and none.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideDefaultGuards(): iterable
    {
        yield 'the sign-in guard' => [self::GUARD];

        yield 'another kind of guard' => ['web'];

        yield 'no guard' => ['not-a-guard'];

        yield 'none' => [''];
    }

    /**
     * Whatever the default guard, the context is the identity and the client,
     * and it is never refused: an event is only described.
     *
     * @param  string  $guard
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDefaultGuards')]
    public function testTheDefaultGuardIsNeverRead(string $guard): void
    {
        $person = $this->createPerson();

        $this->actInTenant($person);

        Config::set('auth.defaults.guard', $guard);

        self::assertSame(self::identityContext($person), $this->adapter()->resolve($person, self::served()));
    }

    /**
     * Bound as MFA's event context resolver, MFA's own events carry the
     * identity and the client MFA hands it, on the application MFA names (none,
     * for an administrator's reset), and none of the sign-in the guard holds.
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
        $expected = self::identityContext($person);

        $this->actInTenant($person);

        Mfa::resetIdentity($person, Actor::of($person), 'Lost device', client: self::served());

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
     * The context of an event about the person, served to the tests' client.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return array<string, int|string|null>
     */
    private static function identityContext(Person $person): array
    {
        return self::context([
            'identity_type' => $person->getMorphClass(),
            'identity_id'   => self::keyOf($person),
            'ip'            => self::IP,
            'user_agent'    => self::USER_AGENT,
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
     * The client the tests' events are served to, as MFA hands it.
     *
     * @return \SineMacula\Laravel\Mfa\Context\ClientContext
     */
    private static function served(): ClientContext
    {
        return new ClientContext(self::IP, self::USER_AGENT);
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
