<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Tenancy\MembershipSet;

/**
 * Memberships for tests: each identity holds what `grant()` gave it, complete
 * unless marked `incomplete()`, and throws once told to `failFor()` it.
 *
 * Bind it before boot for SSO's membership adapters to bind.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeMemberships implements Memberships
{
    /** @var class-string The contract the fake is bound as. */
    public const string MEMBERSHIPS = Memberships::class;

    /** @var array<string, array<string, \SineMacula\Laravel\Iam\Tenancy\Membership>> Each identity's memberships, by identity key then tenant. */
    private array $memberships = [];

    /** @var array<string, bool> Whether each identity's set is incomplete, by key. */
    private array $incomplete = [];

    /** @var array<string, \Throwable> What asking about each identity throws, by key. */
    private array $failures = [];

    /** @var list<array{identity: class-string, id: string}> Every question asked, in order. */
    private array $asked = [];

    /**
     * Bind a fresh fake as the memberships and return it.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function fake(?ContainerContract $container = null): self
    {
        $fake = new self;

        ($container ?? Container::getInstance())->instance(self::MEMBERSHIPS, $fake);

        return $fake;
    }

    /**
     * Grant the membership, replacing any of the same tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Iam\Tenancy\Membership  $membership
     * @return self
     */
    public function grant(Identity $identity, Membership $membership): self
    {
        $this->memberships[self::keyOf($identity)][$membership->tenantId ?? ''] = $membership;

        return $this;
    }

    /**
     * Revoke the tenant's membership, or the platform principal for `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $tenantId
     * @return self
     */
    public function revoke(Identity $identity, ?string $tenantId): self
    {
        unset($this->memberships[self::keyOf($identity)][$tenantId ?? '']);

        return $this;
    }

    /**
     * Answer the identity's set as incomplete from now on.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return self
     */
    public function incomplete(Identity $identity): self
    {
        $this->incomplete[self::keyOf($identity)] = true;

        return $this;
    }

    /**
     * Throw on every question about the identity from now on.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\Throwable  $failure
     * @return self
     */
    public function failFor(Identity $identity, ?\Throwable $failure = null): self
    {
        $this->failures[self::keyOf($identity)] = $failure ?? new \RuntimeException('The fake memberships cannot be read for the identity.');

        return $this;
    }

    /**
     * The identity's granted memberships, unless told to fail.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Iam\Tenancy\MembershipSet
     *
     * @throws \Throwable
     */
    #[\Override]
    public function of(Identity $identity): MembershipSet
    {
        $key = self::keyOf($identity);

        $this->asked[] = ['identity' => $identity::class, 'id' => self::idOf($identity)];

        if (isset($this->failures[$key])) {
            throw $this->failures[$key];
        }

        return new MembershipSet(array_values($this->memberships[$key] ?? []), ($this->incomplete[$key] ?? false) !== true);
    }

    /**
     * Every question asked, in order.
     *
     * @return list<array{identity: class-string, id: string}>
     */
    public function asked(): array
    {
        return $this->asked;
    }

    /**
     * The identity's key: its class and identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return string
     */
    private static function keyOf(Identity $identity): string
    {
        return json_encode([$identity::class, self::idOf($identity)], JSON_THROW_ON_ERROR);
    }

    /**
     * The identity's identifier, as a string.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function idOf(Identity $identity): string
    {
        return IdentifierCoercion::stringify($identity->getAuthIdentifier())
            ?? throw new \InvalidArgumentException('The fake memberships answer for an identity identified by a string or an integer.');
    }
}
