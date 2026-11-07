<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Provisioning;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Fixtures\Models\Person;

/**
 * An application's provisioner, as the tests' application writes one: each
 * result is made a new `Person`, named from the mapped `display_name` when the
 * connection maps one, under an email address of its own (never the one the
 * provider asserts, so no existing person is ever found by it), and that person
 * is made a member of the tenant (`ProvisionedMembership`). Both are written on
 * the default connection, the tests' shared storage connection.
 *
 * A test hands it a closure (`$observe`) to look at the database at each step,
 * given the step's name (`identity` once the person is inserted, `membership`
 * before the membership is), the person and the result; whatever the closure
 * throws propagates, as an application's provisioner refusing throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProvisionsPeople implements Provisioner
{
    /**
     * Constructor.
     *
     * @param  ?\Closure(string, \Tests\Fixtures\Models\Person, \SineMacula\Laravel\Sso\Results\VerifiedResult): void  $observe
     */
    public function __construct(

        /** Looks at the database at each step, or `null`. */
        private ?\Closure $observe = null,
    ) {}

    /**
     * Insert a new person for the result.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    public function createIdentity(#[\SensitiveParameter] VerifiedResult $result): Identity
    {
        $name   = $result->attributes['display_name'] ?? null;
        $person = Person::query()->create([
            'name'  => is_string($name) ? $name : 'Provisioned person',
            'email' => sprintf('provisioned-%s@people.test', bin2hex(random_bytes(8))),
        ]);

        $this->observe('identity', $person, $result);

        return $person;
    }

    /**
     * Insert the person's membership of the tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return void
     */
    #[\Override]
    public function createMembership(Identity $identity, string $tenantId, #[\SensitiveParameter] VerifiedResult $result): void
    {
        assert($identity instanceof Person);

        $this->observe('membership', $identity, $result);

        ProvisionedMembership::query()->create(['person_id' => $identity->id, 'tenant_id' => $tenantId]);
    }

    /**
     * Hand the step, the person and the result to the test's closure, when it
     * gave one.
     *
     * @param  string  $step
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return void
     */
    private function observe(string $step, Person $person, #[\SensitiveParameter] VerifiedResult $result): void
    {
        if ($this->observe === null) {
            return;
        }

        ($this->observe)($step, $person, $result);
    }
}
