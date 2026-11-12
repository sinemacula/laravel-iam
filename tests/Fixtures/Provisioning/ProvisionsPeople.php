<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Provisioning;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Fixtures\Models\Person;

/**
 * The tests' provisioner: a new `Person` and membership per result.
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
     * Hand the step, person and result to the test's closure, if any.
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
