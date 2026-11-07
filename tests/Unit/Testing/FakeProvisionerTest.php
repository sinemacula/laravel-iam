<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher as EventsDispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Events\Dispatcher;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Iam\Testing\FakeProvisioner;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\ProvisionerTests;
use SineMacula\Laravel\Iam\Testing\Seams\ProvisionerContract;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Fixtures\Models\Machine;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\PlainIdentity;

/**
 * Proves the `Provisioner` contract kit against this package's fake provisioner
 * (IAM-7.1): the fake creates each identity through the test's closure, keeps
 * each membership and writes it through a closure when handed one, refuses
 * either once told to, and keeps what it made; and the kit's assertions fail a
 * provisioner that answers an identity it did not insert during the call, the
 * same identity twice, an existing identity, no membership or one that was
 * there before, or an answer for a result it declines.
 *
 * Each person is stored only in memory: an insertion is the `created` event
 * Eloquent's dispatcher carries, dispatched as an insert would dispatch it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeProvisioner::class)]
#[CoversClass(ProvisionerContract::class)]
#[CoversTrait(ProvisionerTests::class)]
final class FakeProvisionerTest extends TestCase
{
    use ProvisionerTests;

    /** @var string The tenant every result's connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var int The key the next identity the closure creates is given. */
    private int $next = 100;

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeProvisioner The fake under test. */
    private ?FakeProvisioner $fake = null;

    /** @var ?\Illuminate\Contracts\Events\Dispatcher Eloquent's dispatcher before the test. */
    private ?EventsDispatcher $events = null;

    /**
     * Give Eloquent a dispatcher of its own, through which each insertion is
     * witnessed.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->events = Model::getEventDispatcher();

        Model::setEventDispatcher(new Dispatcher);
    }

    /**
     * Give Eloquent back the dispatcher it had.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->events === null ? Model::unsetEventDispatcher() : Model::setEventDispatcher($this->events);

        parent::tearDown();
    }

    /**
     * Each identity is the closure's, made for the result asked about, and kept
     * in order.
     *
     * @return void
     */
    public function testEachIdentityIsTheClosuresAndIsKept(): void
    {
        $asked = [];
        $fake  = new FakeProvisioner(function (VerifiedResult $result) use (&$asked): Identity {
            $asked[] = $result;

            return $this->inserted();
        });

        $result = self::verifiedResult();
        $first  = $fake->createIdentity($result);
        $second = $fake->createIdentity($result);

        self::assertSame([$result, $result], $asked);
        self::assertSame([$first, $second], $fake->identities());
        self::assertSame([], $fake->memberships());
    }

    /**
     * Without a closure for memberships, each membership is kept with its
     * tenant, and nothing else is written.
     *
     * @return void
     */
    public function testEachMembershipIsKeptWithItsTenant(): void
    {
        $fake     = $this->fake();
        $identity = $fake->createIdentity(self::verifiedResult());

        $fake->createMembership($identity, self::TENANT, self::verifiedResult());

        self::assertSame([['identity' => $identity, 'tenant' => self::TENANT]], $fake->memberships());
    }

    /**
     * With a closure for memberships, the membership is written by the closure,
     * for the identity and the tenant asked about, and kept.
     *
     * @return void
     */
    public function testAMembershipIsWrittenByTheClosureWhenHandedOne(): void
    {
        $asked   = [];
        $members = static function (Identity $identity, string $tenantId) use (&$asked): void {
            $asked[] = [$identity, $tenantId];
        };

        $fake     = new FakeProvisioner(fn (): Identity => $this->inserted(), $members);
        $result   = self::verifiedResult();
        $identity = $fake->createIdentity($result);

        $fake->createMembership($identity, 'tenant-2', $result);

        self::assertSame([[$identity, 'tenant-2']], $asked);
        self::assertSame([['identity' => $identity, 'tenant' => 'tenant-2']], $fake->memberships());
    }

    /**
     * Once told to, the fake refuses every identity, with the refusal given or
     * one of its own, and makes none.
     *
     * @return void
     */
    public function testAnIdentityIsRefusedOnceToldTo(): void
    {
        $refusal = new \RuntimeException('Declined.');
        $fake    = $this->fake()->refuseIdentities($refusal);

        self::assertSame($refusal, self::thrownBy(static fn (): Identity => $fake->createIdentity(self::verifiedResult())));

        $fake->refuseIdentities();

        $thrown = self::thrownBy(static fn (): Identity => $fake->createIdentity(self::verifiedResult()));

        self::assertInstanceOf(\RuntimeException::class, $thrown);
        self::assertStringContainsString('refuses to create an identity', $thrown->getMessage());
        self::assertSame([], $fake->identities());
    }

    /**
     * Once told to, the fake refuses every membership, with the refusal given
     * or one of its own, and keeps none.
     *
     * @return void
     */
    public function testAMembershipIsRefusedOnceToldTo(): void
    {
        $refusal  = new \RuntimeException('Declined.');
        $fake     = $this->fake();
        $identity = $fake->createIdentity(self::verifiedResult());

        $fake->refuseMemberships($refusal);

        $member = static function () use ($fake, $identity): void {
            $fake->createMembership($identity, self::TENANT, self::verifiedResult());
        };

        self::assertSame($refusal, self::thrownBy($member));

        $fake->refuseMemberships();

        $thrown = self::thrownBy($member);

        self::assertInstanceOf(\RuntimeException::class, $thrown);
        self::assertStringContainsString('refuses to create a membership', $thrown->getMessage());
        self::assertSame([], $fake->memberships());
    }

    /**
     * `fake()` binds a fresh fake as the application's provisioner, in the
     * container given or the global one.
     *
     * @return void
     */
    public function testFakeBindsAFreshFakeAsTheProvisioner(): void
    {
        $container = new Container;
        $create    = fn (): Identity => $this->inserted();
        $fake      = FakeProvisioner::fake($create, null, $container);

        self::assertSame($fake, $container->make(Provisioner::class));

        $previous = Container::getInstance();

        try {
            Container::setInstance($global = new Container);

            $other = FakeProvisioner::fake($create);

            self::assertSame($other, $global->make(FakeProvisioner::PROVISIONER));
            self::assertNotSame($fake, $other);
        } finally {
            Container::setInstance($previous);
        }
    }

    /**
     * The kit fails an identity that is no Eloquent model, which SSO cannot
     * name.
     *
     * @return void
     */
    public function testTheKitFailsAnIdentityThatIsNoModel(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('is no Eloquent model');

        ProvisionerContract::assertCreatesANewIdentity(static fn (): Identity => new PlainIdentity(['id' => 1]));
    }

    /**
     * The kit fails an identity the provisioner found rather than inserted, one
     * it never stored, one it inserted before the call and kept, and one whose
     * insertion it did not let Eloquent dispatch.
     *
     * @return void
     */
    public function testTheKitFailsAnIdentityItDidNotInsert(): void
    {
        $found = self::person(7, inserted: false);

        self::assertKitFails('did not insert', static fn () => ProvisionerContract::assertCreatesANewIdentity(static fn (): Identity => $found));

        $unsaved                     = new Person;
        $unsaved->wasRecentlyCreated = true;

        self::assertKitFails('did not insert', static fn () => ProvisionerContract::assertCreatesANewIdentity(static fn (): Identity => $unsaved));

        $kept = $this->inserted();

        self::assertKitFails('did not insert', static fn () => ProvisionerContract::assertCreatesANewIdentity(static fn (): Identity => $kept));

        $quiet = fn (): Identity => Model::withoutEvents(fn (): Person => $this->inserted());

        self::assertKitFails('did not insert', static fn () => ProvisionerContract::assertCreatesANewIdentity($quiet));
    }

    /**
     * The kit fails a provisioner that answers the identity it created before,
     * however it comes to insert it again.
     *
     * @return void
     */
    public function testTheKitFailsTheSameIdentityTwice(): void
    {
        $key     = null;
        $answers = 0;

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('answered the identity it created before');

        ProvisionerContract::assertCreatesANewIdentity(function () use (&$key, &$answers): Identity {
            $answers++;

            if ($key === null) {
                $first = $this->inserted();
                $key   = self::keyOf($first);

                return $first;
            }

            return $answers === 2 ? self::person($key, inserted: true) : self::fail('Asked too often.');
        });
    }

    /**
     * The kit fails a provisioner that answers an existing identity whose
     * attributes the result matches, as if it had inserted it.
     *
     * @return void
     */
    public function testTheKitFailsAnExistingIdentity(): void
    {
        $existing = self::person(7, inserted: false);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('answered an existing identity');

        ProvisionerContract::assertNeverAnswersAnExistingIdentity(static fn (): Identity => self::person(7, inserted: true), $existing);
    }

    /**
     * The kit tells a new identity apart from an existing one that is no
     * Eloquent model.
     *
     * @return void
     */
    public function testTheKitTellsANewIdentityFromAnExistingOneThatIsNoModel(): void
    {
        ProvisionerContract::assertNeverAnswersAnExistingIdentity(fn (): Identity => $this->inserted(), new PlainIdentity(['id' => 100]));

        $this->addToAssertionCount(1);
    }

    /**
     * The kit tells a new identity apart from an existing one of another model
     * under the same key.
     *
     * @return void
     */
    public function testTheKitTellsANewIdentityFromAnExistingOneOfAnotherModel(): void
    {
        $existing = new Machine;

        $existing->setRawAttributes(['id' => 100], true);

        ProvisionerContract::assertNeverAnswersAnExistingIdentity(fn (): Identity => $this->inserted(), $existing);

        $this->addToAssertionCount(1);
    }

    /**
     * The kit fails a provisioner that creates no membership.
     *
     * @return void
     */
    public function testTheKitFailsAProvisionerThatCreatesNoMembership(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('did not create the new identity\'s membership');

        ProvisionerContract::assertCreatesTheMembership(static function (): void {}, static fn (): bool => false);
    }

    /**
     * The kit fails a membership the identity held before the provisioner was
     * asked for it.
     *
     * @return void
     */
    public function testTheKitFailsAMembershipThatWasThereBefore(): void
    {
        $asked = false;

        self::assertKitFails('was a member of the tenant before', static fn () => ProvisionerContract::assertCreatesTheMembership(static function () use (&$asked): void {
            $asked = true;
        }, static fn (): bool => true));

        self::assertFalse($asked);
    }

    /**
     * The kit's check that an existing identity is never answered fails a
     * provisioner that answers it.
     *
     * @return void
     */
    public function testTheKitsCheckFailsAProvisionerAnsweringTheExistingIdentity(): void
    {
        $existing   = $this->existingIdentity();
        $this->fake = new FakeProvisioner(static fn (): Identity => $existing);

        $check = new \ReflectionMethod($this, 'testProvisionerNeverAnswersAnExistingIdentity');

        self::assertTrue($check->isPublic(), 'The kit\'s check is not public, so PHPUnit would not run it.');

        $this->expectException(AssertionFailedError::class);

        $this->testProvisionerNeverAnswersAnExistingIdentity();
    }

    /**
     * Every check of the kit is a public test, so a test case using it runs
     * each one.
     *
     * @return void
     */
    public function testEveryCheckOfTheKitIsAPublicTest(): void
    {
        $methods = (new \ReflectionClass(ProvisionerTests::class))->getMethods();
        $checks  = array_values(array_filter($methods, static fn (\ReflectionMethod $method): bool => str_starts_with($method->getName(), 'test')));

        self::assertCount(4, $checks);

        foreach ($checks as $check) {
            self::assertTrue($check->isPublic(), sprintf('The kit\'s [%s] is not public.', $check->getName()));
        }
    }

    /**
     * The kit fails a provisioner that answers for a result it declines.
     *
     * @return void
     */
    public function testTheKitFailsAnAnswerForADeclinedResult(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('answered for a result it declines');

        ProvisionerContract::assertRefusesByThrowing(fn (): Identity => $this->inserted());
    }

    /**
     * The fake under test.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\Provisioner
     */
    #[\Override]
    protected function provisioner(): Provisioner
    {
        return $this->fake();
    }

    /**
     * A result the fake provisions for.
     *
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    #[\Override]
    protected function provisionedResult(): VerifiedResult
    {
        return self::verifiedResult();
    }

    /**
     * An identity that already exists.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    #[\Override]
    protected function existingIdentity(): Identity
    {
        return self::person(1, inserted: false);
    }

    /**
     * A result carrying the existing identity's email address.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $existing
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    #[\Override]
    protected function resultMatching(Identity $existing): VerifiedResult
    {
        self::assertInstanceOf(Person::class, $existing);

        return self::verifiedResult(['email' => $existing->getRawOriginal('email')]);
    }

    /**
     * A result the fake declines, once told to decline every one.
     *
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    #[\Override]
    protected function declinedResult(): VerifiedResult
    {
        $this->fake()->refuseIdentities();

        return self::verifiedResult();
    }

    /**
     * Whether the fake kept a membership of the identity of the tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @return bool
     */
    #[\Override]
    protected function isMemberOf(Identity $identity, string $tenantId): bool
    {
        return in_array(['identity' => $identity, 'tenant' => $tenantId], $this->fake()->memberships(), true);
    }

    /**
     * The fake under test, made once per test, creating a new person each time
     * it is asked.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeProvisioner
     */
    private function fake(): FakeProvisioner
    {
        return $this->fake ??= new FakeProvisioner(fn (): Identity => $this->inserted());
    }

    /**
     * A new person, as an insert leaves it, under the next key.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    private function inserted(): Person
    {
        return self::person($this->next++, inserted: true);
    }

    /**
     * A stored person under the key, inserted now, Eloquent's dispatcher
     * carrying its `created` event as an insert would, or found.
     *
     * @param  int  $key
     * @param  bool  $inserted
     * @return \Tests\Fixtures\Models\Person
     */
    private static function person(int $key, bool $inserted): Person
    {
        $person = new Person;

        $person->setRawAttributes(['id' => $key, 'email' => sprintf('person-%d@example.test', $key)], true);

        $person->exists             = true;
        $person->wasRecentlyCreated = $inserted;

        if ($inserted) {
            Model::getEventDispatcher()?->dispatch('eloquent.created: ' . Person::class, $person);
        }

        return $person;
    }

    /**
     * The person's key.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return int
     */
    private static function keyOf(Person $person): int
    {
        $key = $person->getKey();

        return is_int($key) ? $key : self::fail('The person has no key.');
    }

    /**
     * A `sign_in` result verified through a connection of the tenant, with the
     * attributes given.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private static function verifiedResult(array $attributes = []): VerifiedResult
    {
        return new VerifiedResult(
            'https://idp.example.test',
            'subject-1',
            null,
            'connection-1',
            self::TENANT,
            'oidc',
            'api',
            Purpose::SIGN_IN,
            RequestReference::fromString('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
            $attributes,
            false,
            new AuthenticationContext(CarbonImmutable::now()->startOfSecond()),
        );
    }

    /**
     * What the closure throws, failing the test unless it throws.
     *
     * @param  \Closure(): mixed  $call
     * @return \Throwable
     */
    private static function thrownBy(\Closure $call): \Throwable
    {
        try {
            $call();
        } catch (\Throwable $exception) {
            return $exception;
        }

        self::fail('Nothing was thrown.');
    }

    /**
     * Assert the kit's assertion fails with a message containing the text.
     *
     * @param  string  $message
     * @param  \Closure(): void  $assertion
     * @return void
     */
    private static function assertKitFails(string $message, \Closure $assertion): void
    {
        $thrown = self::thrownBy($assertion);

        self::assertInstanceOf(AssertionFailedError::class, $thrown);
        self::assertStringContainsString($message, $thrown->getMessage());
    }
}
