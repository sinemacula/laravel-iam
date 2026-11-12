<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Iam\Mfa\EventContextResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Events\EventSubject;
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
 * Tests for MFA's event context, filled from the subject MFA hands it.
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

    /** @var string Another session guard, beside the one people sign in on. */
    private const string ADMIN = 'admin';

    /** @var ?\Tests\Fixtures\Models\Person The identity MFA's contract kit asks about. */
    private ?Person $eventPerson = null;

    /**
     * The identity's named sign-in names its session, principal and tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANamedSignInOfTheIdentitysNamesItsSession(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInTenant($person);

        $this->serveAnotherSession($this->createPerson());

        self::assertSame(self::context([
            'identity_type'  => $person->getMorphClass(),
            'identity_id'    => self::keyOf($person),
            'principal_type' => $person->getMorphClass(),
            'principal_id'   => self::keyOf($person),
            'tenant_id'      => self::TENANT,
            'session_id'     => self::referenceOf($session),
            'ip'             => self::IP,
            'user_agent'     => self::USER_AGENT,
        ]), $this->adapter()->resolve(new EventSubject($person, self::GUARD, self::referenceOf($session), self::served())));
    }

    /**
     * Another identity's session names no session, principal or tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherIdentitysSessionNamesNone(): void
    {
        $person = $this->createPerson();
        $other  = $this->signInTenant($this->createPerson());

        $this->serveAnotherSession($person);

        self::assertSame(self::identityContext($person), $this->adapter()->resolve(new EventSubject($person, self::GUARD, self::referenceOf($other), self::served())));
    }

    /**
     * A session on another application names none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherApplicationsSessionNamesNone(): void
    {
        $person = $this->createPerson();
        $admin  = $this->signIn($person, self::ADMIN)->record;

        $this->serveAnotherSession($person);

        self::assertSame(self::identityContext($person), $this->adapter()->resolve(new EventSubject($person, self::GUARD, self::referenceOf($admin), self::served())));
    }

    /**
     * Rows of `[sign-in]` that name no session.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnknownSignIns(): iterable
    {
        yield 'an unknown id' => ['01890a5d-ac96-774b-bcce-b302099a8057'];

        yield 'a malformed id' => ['not-a-session-key'];
    }

    /**
     * A sign-in that names no session names none and is not refused.
     *
     * @param  string  $signIn
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnknownSignIns')]
    public function testASignInThatNamesNoSessionNamesNone(string $signIn): void
    {
        $person = $this->createPerson();

        $this->serveAnotherSession($person);

        self::assertSame(self::identityContext($person), $this->adapter()->resolve(new EventSubject($person, self::GUARD, $signIn, self::served())));
    }

    /**
     * Rows of `[application, named]` naming only one of the two.
     *
     * @return iterable<string, array{0: ?string, 1: bool}>
     */
    public static function providePartialSubjects(): iterable
    {
        yield 'no sign-in' => [self::GUARD, false];

        yield 'no application' => [null, true];
    }

    /**
     * Without both the application and the sign-in, no session is named.
     *
     * @param  ?string  $application
     * @param  bool  $named
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('providePartialSubjects')]
    public function testASubjectNamingLessThanBothNamesNone(?string $application, bool $named): void
    {
        $person  = $this->createPerson();
        $session = $this->serveAnotherSession($person);
        $signIn  = $named ? self::referenceOf($session) : null;

        self::assertSame(self::identityContext($person), $this->adapter()->resolve(new EventSubject($person, $application, $signIn, self::served())));
    }

    /**
     * What cannot be resolved names no session and is never refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWhatCannotBeResolvedIsNeverRefused(): void
    {
        $person  = $this->createPerson();
        $session = $this->serveAnotherSession($person);

        self::assertSame(self::identityContext($person), $this->adapter()->resolve(new EventSubject($person, 'not-a-guard', self::referenceOf($session), self::served())));

        $stranger = new class extends User implements MultiFactorAuthenticatable {
            use HasFactors;
        };

        $stranger->setAttribute('id', 7);

        $context = $this->adapter()->resolve(new EventSubject($stranger, self::GUARD, self::referenceOf($session), self::served()));

        self::assertSame('7', $context['identity_id']);
        self::assertSame([null, null, null, null], [$context['session_id'], $context['principal_type'], $context['principal_id'], $context['tenant_id']]);
    }

    /**
     * A session with no principal and no tenant names its session alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionActingAsNoPrincipalNamesItsSessionAlone(): void
    {
        $person    = $this->createPerson();
        $session   = $this->signIn($person)->record;
        $principal = $session->principal();

        $session->forceFill([$principal->getMorphType() => null, $principal->getForeignKeyName() => null])->save();

        $context = $this->adapter()->resolve(new EventSubject($person, self::GUARD, self::referenceOf($session), self::served()));

        self::assertSame(self::referenceOf($session), $context['session_id']);
        self::assertSame([null, null, null], [$context['principal_type'], $context['principal_id'], $context['tenant_id']]);
    }

    /**
     * The identity and the principal are carried by their morph class.
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

            $session = $this->signInTenant($person);
            $context = $this->adapter()->resolve(new EventSubject($person, self::GUARD, self::referenceOf($session), self::served()));
        } finally {
            Relation::morphMap($previous, false);
        }

        self::assertSame(self::MORPH, $context['identity_type']);
        self::assertSame(self::MORPH, $context['principal_type']);
    }

    /**
     * An event about no identity carries only the client.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEventAboutNoIdentityCarriesOnlyTheClient(): void
    {
        $session = $this->serveAnotherSession($this->createPerson());

        self::assertSame(self::context([
            'ip'         => self::IP,
            'user_agent' => self::USER_AGENT,
        ]), $this->adapter()->resolve(new EventSubject(null, self::GUARD, self::referenceOf($session), self::served())));
    }

    /**
     * Without a client, no IP address or user agent is named.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAClientNoneIsNamed(): void
    {
        $person = $this->createPerson();

        $this->serveAnotherSession($person);

        self::assertSame(self::context([
            'identity_type' => $person->getMorphClass(),
            'identity_id'   => self::keyOf($person),
        ]), $this->adapter()->resolve(new EventSubject($person)));
    }

    /**
     * No tenant is carried for a subject naming no sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoTenantIsCarriedWithoutASignIn(): void
    {
        $person = $this->createPerson();

        $this->serveAnotherSession($person);
        $this->actingInTenant(new ClaimedTenant('tenant-claimed'));

        self::assertNull($this->adapter()->resolve(new EventSubject($person, self::GUARD, null, self::served()))['tenant_id']);
    }

    /**
     * Rows of `[default guard]`.
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
     * The default guard is never read.
     *
     * @param  string  $guard
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDefaultGuards')]
    public function testTheDefaultGuardIsNeverRead(string $guard): void
    {
        $person  = $this->createPerson();
        $session = $this->signInTenant($person);

        $this->serveAnotherSession($person);

        Config::set('auth.defaults.guard', $guard);

        $context = $this->adapter()->resolve(new EventSubject($person, self::GUARD, self::referenceOf($session), self::served()));

        self::assertSame(self::referenceOf($session), $context['session_id']);
        self::assertSame(self::TENANT, $context['tenant_id']);
    }

    /**
     * Once bound, MFA's own events carry the context.
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

        $this->serveAnotherSession($person);

        Mfa::resetIdentity($person, Actor::of($person), 'Lost device', client: self::served());

        Event::assertDispatched(FactorsReset::class, static fn (FactorsReset $event): bool => $event->context === $expected);
    }

    /**
     * Declare another session guard beside the one people sign in on.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        Config::set('auth.guards.' . self::ADMIN, ['driver' => 'jwt', 'provider' => 'people', 'application' => ['methods' => ['password']]]);
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
     * An identity events are about, for MFA's contract kit.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function eventIdentity(): MultiFactorAuthenticatable
    {
        return $this->eventPerson ??= $this->createPerson();
    }

    /**
     * Serve the kit identity's session, with another client's request bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    protected function arrangeServedEventSession(): void
    {
        $identity = $this->eventIdentity();

        self::assertInstanceOf(Person::class, $identity);

        $this->serveAnotherSession($identity);
    }

    /**
     * A sign-in of the kit's identity on the guard, which the resolver names.
     *
     * @return array{0: string, 1: string}
     *
     * @throws \Throwable
     */
    protected function knownEventSignIn(): array
    {
        $identity = $this->eventIdentity();

        self::assertInstanceOf(Person::class, $identity);

        return [self::GUARD, self::referenceOf($this->signIn($identity)->record)];
    }

    /**
     * The context of an event about the person, naming no sign-in.
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
     * Sign the person in and record the tenant on the new session's row.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function signInTenant(Person $person): EloquentSession&Model
    {
        $session = $this->signIn($person)->record;

        $session->forceFill([$session->getTenantIdName() => self::TENANT])->save();

        return $session;
    }

    /**
     * Serve another session of the person's in the tenant, and return it.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function serveAnotherSession(Person $person): EloquentSession&Model
    {
        $session = $this->signInTenant($person);

        $this->actingOnSession($session, self::GUARD);
        $this->bindStrayRequest();

        return $session;
    }

    /**
     * The sign-in MFA names the session by.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return string
     *
     * @throws \Throwable
     */
    private static function referenceOf(EloquentSession&Model $session): string
    {
        return SignIn::reference($session, (string) $session->getGuard());
    }

    /**
     * A context with the values given and every other key `null`.
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
