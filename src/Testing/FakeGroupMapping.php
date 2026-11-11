<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;

/**
 * A group mapping for tests (IAM-7.2): each group maps to the grants the test
 * gave it (`map()`), any other to nothing, and every question throws once told
 * to `refuse()`. `fake()` binds a fresh instance.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeGroupMapping implements GroupMapping
{
    /** @var class-string The contract the fake is bound as. */
    public const string MAPPING = GroupMapping::class;

    /** @var array<string, list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>> The grants each group maps to, by its name. */
    private array $map = [];

    /** @var ?\Throwable What every question throws, once the test has it refuse. */
    private ?\Throwable $refusal = null;

    /** @var list<array{connection: string, tenant: string, groups: list<string>}> Every question asked, in order. */
    private array $asked = [];

    /**
     * Bind a fresh fake as the application's group mapping in the container
     * given, or the application's own, and return it.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function fake(?ContainerContract $container = null): self
    {
        $fake = new self;

        ($container ?? Container::getInstance())->instance(self::MAPPING, $fake);

        return $fake;
    }

    /**
     * Have the group map to the grants given from now on: a role's name, which
     * holds in the connection's tenant alone, or a grant instruction.
     *
     * @param  string  $group
     * @param  \SineMacula\Laravel\Iam\Provisioning\GrantInstruction|string  ...$grants
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function map(string $group, GrantInstruction|string ...$grants): self
    {
        $instruction = static fn (GrantInstruction|string $grant): GrantInstruction => is_string($grant) ? GrantInstruction::role($grant) : $grant;

        $this->map[$group] = array_values(array_map($instruction, $grants));

        return $this;
    }

    /**
     * Have every question throw from now on, as an application's mapping that
     * declines a result does.
     *
     * @param  ?\Throwable  $refusal
     * @return self
     */
    public function refuse(?\Throwable $refusal = null): self
    {
        $this->refusal = $refusal ?? new \RuntimeException('The fake group mapping refuses to map the groups.');

        return $this;
    }

    /**
     * The grants the groups map to, each once, or throw the refusal the test
     * told it to.
     *
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  list<string>  $groups
     * @return list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>
     *
     * @throws \Throwable
     */
    #[\Override]
    public function grantsFor(string $connectionId, string $tenantId, array $groups): array
    {
        $this->asked[] = ['connection' => $connectionId, 'tenant' => $tenantId, 'groups' => $groups];

        if ($this->refusal !== null) {
            throw $this->refusal;
        }

        $grants = [];

        foreach ($groups as $group) {
            $grants = [...$grants, ...$this->map[$group] ?? []];
        }

        return array_values(array_unique($grants, SORT_REGULAR));
    }

    /**
     * Every question asked, in order: the connection, the tenant and the
     * groups.
     *
     * @return list<array{connection: string, tenant: string, groups: list<string>}>
     */
    public function asked(): array
    {
        return $this->asked;
    }
}
