<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * A provisioner for tests (IAM-7.1): each identity it is asked for is made by
 * the closure the test hands it, which inserts one of the application's own
 * identity models, with its model events on, and each membership is kept, and
 * written by a second closure when the test hands it one. A test can have
 * either refuse (`refuseIdentities()`, `refuseMemberships()`), as an
 * application's provisioner that declines a result throws.
 *
 * Every identity and membership it made is kept (`identities()`,
 * `memberships()`: the identity and the tenant), in order, whether or not the
 * listener's transaction then committed: what is stored is the database's to
 * tell, so a test reads the rows to see what a rollback undid.
 *
 * Call `FakeProvisioner::fake($create)`, which binds a fresh instance as the
 * application's provisioner and returns it; a provisioner bound in the
 * container counts as named in `iam.provisioning.provisioner`, whenever it is
 * bound, so provisioning is on from then. It satisfies this package's own
 * `Seams\Concerns\ProvisionerTests` kit while the closure creates a new
 * identity each time. Not for production use.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeProvisioner implements Provisioner
{
    /** @var class-string The contract the fake is bound as. */
    public const string PROVISIONER = Provisioner::class;

    /** @var list<\SineMacula\Laravel\Authentication\Contracts\Identity> Every identity made, in order. */
    private array $identities = [];

    /** @var list<array{identity: \SineMacula\Laravel\Authentication\Contracts\Identity, tenant: string}> Every membership made, in order. */
    private array $memberships = [];

    /** @var ?\Throwable What asking for an identity throws, once the test has it refuse. */
    private ?\Throwable $identityRefusal = null;

    /** @var ?\Throwable What asking for a membership throws, once the test has it refuse. */
    private ?\Throwable $membershipRefusal = null;

    /**
     * Constructor.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Results\VerifiedResult): \SineMacula\Laravel\Authentication\Contracts\Identity  $create
     * @param  ?\Closure(\SineMacula\Laravel\Authentication\Contracts\Identity, string): void  $member
     */
    public function __construct(

        /** Creates a new identity of the application's for a result. */
        private readonly \Closure $create,

        /** Writes the identity's membership of a tenant, or `null` to keep it alone. */
        private readonly ?\Closure $member = null,
    ) {}

    /**
     * Bind a fresh fake as the application's provisioner in the container
     * given, or the application's own, and return it.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Results\VerifiedResult): \SineMacula\Laravel\Authentication\Contracts\Identity  $create
     * @param  ?\Closure(\SineMacula\Laravel\Authentication\Contracts\Identity, string): void  $member
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function fake(\Closure $create, ?\Closure $member = null, ?ContainerContract $container = null): self
    {
        $fake = new self($create, $member);

        ($container ?? Container::getInstance())->instance(self::PROVISIONER, $fake);

        return $fake;
    }

    /**
     * Have every request for an identity throw from now on, as an application's
     * provisioner that declines a result does.
     *
     * @param  ?\Throwable  $refusal
     * @return self
     */
    public function refuseIdentities(?\Throwable $refusal = null): self
    {
        $this->identityRefusal = $refusal ?? new \RuntimeException('The fake provisioner refuses to create an identity.');

        return $this;
    }

    /**
     * Have every request for a membership throw from now on, as an
     * application's provisioner that declines a tenant does.
     *
     * @param  ?\Throwable  $refusal
     * @return self
     */
    public function refuseMemberships(?\Throwable $refusal = null): self
    {
        $this->membershipRefusal = $refusal ?? new \RuntimeException('The fake provisioner refuses to create a membership.');

        return $this;
    }

    /**
     * Create a new identity for the result through the test's closure, or throw
     * the refusal the test told it to.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \Throwable
     */
    #[\Override]
    public function createIdentity(#[\SensitiveParameter] VerifiedResult $result): Identity
    {
        if ($this->identityRefusal !== null) {
            throw $this->identityRefusal;
        }

        $identity = ($this->create)($result);

        $this->identities[] = $identity;

        return $identity;
    }

    /**
     * Create the identity's membership of the tenant, through the test's
     * closure when it handed one, and keep it, or throw the refusal the test
     * told it to.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    public function createMembership(Identity $identity, string $tenantId, #[\SensitiveParameter] VerifiedResult $result): void
    {
        if ($this->membershipRefusal !== null) {
            throw $this->membershipRefusal;
        }

        if ($this->member !== null) {
            ($this->member)($identity, $tenantId);
        }

        $this->memberships[] = ['identity' => $identity, 'tenant' => $tenantId];
    }

    /**
     * Every identity made so far, in order.
     *
     * @return list<\SineMacula\Laravel\Authentication\Contracts\Identity>
     */
    public function identities(): array
    {
        return $this->identities;
    }

    /**
     * Every membership made so far, in order: the identity and the tenant.
     *
     * @return list<array{identity: \SineMacula\Laravel\Authentication\Contracts\Identity, tenant: string}>
     */
    public function memberships(): array
    {
        return $this->memberships;
    }
}
