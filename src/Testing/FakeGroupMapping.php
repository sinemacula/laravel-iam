<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;

/**
 * A group mapping for tests: each group maps to the grants `map()` gave it, and
 * every question throws once told to `refuse()`.
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

    /** @var ?\Throwable What every question throws once told to refuse. */
    private ?\Throwable $refusal = null;

    /** @var list<array{connection: string, tenant: string, groups: list<string>}> Every question asked, in order. */
    private array $asked = [];

    /**
     * Bind a fresh fake as the group mapping and return it.
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
     * Map the group to the grants; a string is a role in the connection's
     * tenant.
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
     * Throw on every question from now on.
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
     * The grants the groups map to, each once, unless told to refuse.
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
     * Every question asked, in order.
     *
     * @return list<array{connection: string, tenant: string, groups: list<string>}>
     */
    public function asked(): array
    {
        return $this->asked;
    }
}
