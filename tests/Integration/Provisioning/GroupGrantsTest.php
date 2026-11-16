<?php

declare(strict_types = 1);

namespace Tests\Integration\Provisioning;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;
use SineMacula\Laravel\Iam\Provisioning\GroupGrants;
use Tests\Concerns\MigratesAuthorization;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for writing the roles a person's provider groups give,
 * through `laravel-authorization`'s grant service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GroupGrants::class)]
final class GroupGrantsTest extends TestCase
{
    use MigratesAuthorization;

    /** @var string The tenant the groups grant in. */
    private const string TENANT = 'tenant-1';

    /** @var string A role granted in the tenant alone. */
    private const string VIEWER = 'invoices.viewer';

    /** @var string A role granted across the tenant's subtree. */
    private const string APPROVER = 'invoices.approver';

    /**
     * Store the roles, and resolve every tenant to the organisation of its id.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        foreach ([self::VIEWER, self::APPROVER] as $role) {
            Role::query()->create(['name' => $role]);
        }

        $this->app?->instance(TenantResolver::class, new OrganisationTenancy);
    }

    /**
     * Rows of `[method]`, each way the groups' roles are written.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideWrites(): iterable
    {
        yield 'a grant' => ['grant'];

        yield 'a sync' => ['sync'];
    }

    /**
     * Each role is written once, with its reach, a role answered twice
     * included.
     *
     * @param  string  $method
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideWrites')]
    public function testEachRoleIsWrittenOnceWithItsReach(string $method): void
    {
        $person   = $this->person();
        $assigned = $this->recordAssignments();

        $this->write($method, $person, [GrantInstruction::role(self::VIEWER), GrantInstruction::roleWithSubtree(self::APPROVER), GrantInstruction::role(self::VIEWER)]);

        self::assertSame([self::APPROVER => [true, null], self::VIEWER => [false, null]], $this->rolesOf($person));
        self::assertSame([self::VIEWER, self::APPROVER], $assigned->names);
    }

    /**
     * The roles are written as one operation.
     *
     * @param  string  $method
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideWrites')]
    public function testTheRolesAreWrittenAsOneOperation(string $method): void
    {
        $person   = $this->person();
        $assigned = $this->recordAssignments();

        $this->write($method, $person, [GrantInstruction::role(self::VIEWER), GrantInstruction::roleWithSubtree(self::APPROVER)]);

        self::assertCount(2, $assigned->operations);
        self::assertCount(1, array_unique($assigned->operations));
    }

    /**
     * Rows of `[method, name]`, each way the groups' roles are written, with
     * the name the other reach is given under.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideBothReaches(): iterable
    {
        foreach (self::provideWrites() as $write => [$method]) {
            yield $write => [$method, self::VIEWER];

            yield "{$write}, under a name the collation folds" => [$method, strtoupper(self::VIEWER)];
        }
    }

    /**
     * A role given both reaches, compared by the role each name resolves to, is
     * refused before anything is written.
     *
     * @param  string  $method
     * @param  string  $name
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideBothReaches')]
    public function testARoleGivenBothReachesIsRefused(string $method, string $name): void
    {
        if (!Role::query()->where('name', $name)->exists()) {
            self::markTestSkipped('The collation tells the names apart.');
        }

        $person = $this->person();

        try {
            $this->apply($method, $person, [GrantInstruction::role(self::VIEWER), GrantInstruction::roleWithSubtree($name)]);

            self::fail('A role given both reaches was written.');
        } catch (\InvalidArgumentException) {
            self::assertSame([], $this->rolesOf($person));
        }
    }

    /**
     * A re-sync leaves a role held live with its reach and expiry as it is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReSyncLeavesALiveRoleAsItIs(): void
    {
        $person    = $this->person();
        $expiresAt = CarbonImmutable::now('UTC')->addWeek()->startOfSecond();

        $this->grantDirectly($person, self::VIEWER, false, $expiresAt);

        $assigned = $this->recordAssignments();

        $this->write('sync', $person, [GrantInstruction::role(self::VIEWER)]);

        self::assertSame([self::VIEWER => [false, $expiresAt->getTimestamp()]], $this->rolesOf($person));
        self::assertSame([], $assigned->names);
    }

    /**
     * A re-sync that gives a held role the other reach changes it in place,
     * keeping its expiry, in one write.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReSyncChangesAHeldRolesReachInPlace(): void
    {
        $person    = $this->person();
        $expiresAt = CarbonImmutable::now('UTC')->addWeek()->startOfSecond();

        $this->grantDirectly($person, self::APPROVER, false, $expiresAt);

        $assigned = $this->recordAssignments();

        $this->write('sync', $person, [GrantInstruction::roleWithSubtree(self::APPROVER)]);

        self::assertSame([self::APPROVER => [true, $expiresAt->getTimestamp()]], $this->rolesOf($person));
        self::assertSame([self::APPROVER], $assigned->names);
    }

    /**
     * A re-sync revokes a role the instructions no longer give.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReSyncRevokesARoleNoLongerGiven(): void
    {
        $person = $this->person();

        $this->write('grant', $person, [GrantInstruction::role(self::VIEWER), GrantInstruction::roleWithSubtree(self::APPROVER)]);
        $this->write('sync', $person, [GrantInstruction::roleWithSubtree(self::APPROVER)]);

        self::assertSame([self::APPROVER => [true, null]], $this->rolesOf($person));
    }

    /**
     * Write the instructions through the method named, in a transaction.
     *
     * @param  string  $method
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>  $instructions
     * @return void
     *
     * @throws \Throwable
     */
    private function write(string $method, Person $person, array $instructions): void
    {
        Iam::transaction(fn () => $this->apply($method, $person, $instructions));
    }

    /**
     * Write the instructions through the method named, outside a transaction.
     *
     * @param  string  $method
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>  $instructions
     * @return void
     *
     * @throws \Throwable
     */
    private function apply(string $method, Person $person, array $instructions): void
    {
        $grants = $this->app?->make(GroupGrants::class) ?? self::fail('The application has not booted.');

        if ($method === 'grant') {
            $grants->grant($person, self::TENANT, $instructions);
        } else {
            $grants->sync($person, self::TENANT, $instructions);
        }
    }

    /**
     * Grant the person the role in the tenant until the expiry, as an
     * administrator would.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $role
     * @param  bool  $includeSubtree
     * @param  \DateTimeInterface  $expiresAt
     * @return void
     *
     * @throws \Throwable
     */
    private function grantDirectly(Person $person, string $role, bool $includeSubtree, \DateTimeInterface $expiresAt): void
    {
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        Iam::transaction(static fn () => $service->grantRole($person, $role, $expiresAt, tenant: new Reference(Organisation::TYPE, self::TENANT), includeSubtree: $includeSubtree));
    }

    /**
     * Record the name and operation id of each role assigned from now on, in
     * order.
     *
     * @return object{names: list<string>, operations: list<string>}
     */
    private function recordAssignments(): object
    {
        $assigned = new class {
            /** @var list<string> The name of each role assigned, in order. */
            public array $names = [];

            /** @var list<string> The operation id of each assignment, in order. */
            public array $operations = [];
        };

        Event::listen(RoleAssigned::class, static function (RoleAssigned $event) use ($assigned): void {
            $assigned->names[]      = $event->name;
            $assigned->operations[] = $event->operation->id;
        });

        return $assigned;
    }

    /**
     * A stored person.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    private function person(): Person
    {
        return Person::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);
    }

    /**
     * The roles the person holds in the tenant, each by its name, with whether
     * it reaches the subtree and its expiry as a timestamp, ordered by name.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return array<string, array{bool, ?int}>
     */
    private function rolesOf(Person $person): array
    {
        $rows = DB::table('authorizable_roles')
            ->join('roles', 'roles.id', '=', 'authorizable_roles.role_id')
            ->where('authorizable_roles.authorizable_type', $person->getMorphClass())
            ->where('authorizable_roles.authorizable_id', (string) $person->id)
            ->where('authorizable_roles.tenant_type', Organisation::TYPE)
            ->where('authorizable_roles.tenant_id', self::TENANT)
            ->orderBy('roles.name')
            ->get(['roles.name', 'authorizable_roles.include_subtree', 'authorizable_roles.expires_at']);

        $roles = [];

        foreach ($rows as $row) {

            self::assertIsString($row->name);

            $expiresAt = $row->expires_at === null ? null : CarbonImmutable::parse(self::stringOf($row->expires_at), 'UTC')->getTimestamp();

            $roles[$row->name] = [filter_var($row->include_subtree, FILTER_VALIDATE_BOOL), $expiresAt];
        }

        return $roles;
    }

    /**
     * The value as a string, failing on any other.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function stringOf(mixed $value): string
    {
        return is_string($value) ? $value : self::fail('The expiry is not stored as a string.');
    }
}
