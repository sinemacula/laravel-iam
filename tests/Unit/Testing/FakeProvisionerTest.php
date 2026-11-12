<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Iam\Testing\FakeProvisioner;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Fixtures\Models\Person;

/**
 * Unit tests for the fake provisioner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeProvisioner::class)]
final class FakeProvisionerTest extends TestCase
{
    /** @var string The tenant every result's connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var int The key the next identity the closure creates is given. */
    private int $next = 100;

    /**
     * Each identity comes from the closure and is kept in order.
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
     * Without a closure, each membership is only kept with its tenant.
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
     * With a closure, each membership is written by it and kept.
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
     * Once told to, the fake refuses every identity and makes none.
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
     * Once told to, the fake refuses every membership and keeps none.
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
     * `fake()` binds a fresh fake as the provisioner.
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
     * A fake creating a new person each time it is asked.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeProvisioner
     */
    private function fake(): FakeProvisioner
    {
        return new FakeProvisioner(fn (): Identity => $this->inserted());
    }

    /**
     * A new person, as an insert leaves it, under the next key.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    private function inserted(): Person
    {
        $person = new Person;

        $person->setRawAttributes(['id' => $this->next++], true);

        $person->exists             = true;
        $person->wasRecentlyCreated = true;

        return $person;
    }

    /**
     * A `sign_in` result verified through a connection of the tenant.
     *
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private static function verifiedResult(): VerifiedResult
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
            [],
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
}
