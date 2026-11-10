<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\RecordingGrantHook;
use Tests\Fixtures\Authorization\Staff;
use Tests\TestCase;

/**
 * Integration tests of a grant made to an identity that is no principal
 * (IAM-6.1, AUTHZ-2.2, AUTHZ-11.3), with this package's subject resolver bound:
 * the identity is its own subject, so the grant hook finds it the recipient of
 * the grant and the grant is written, and a check about it, through
 * `laravel-authorization`'s manager and Laravel's Gate alike, is decided on its
 * own grants rather than refused.
 *
 * The grant is written inside `laravel-authorization`'s transaction, where its
 * widening classifier reads the grantee's grants with locking reads, so it runs
 * at the connection's own level on every engine, then at READ COMMITTED and
 * REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectResolverAdapter::class)]
final class IdentityGranteeTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /**
     * Store the invoice permissions, so they can be granted.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        foreach (InvoicePermission::cases() as $permission) {
            Permission::query()->create(['name' => $permission->value]);
        }
    }

    /**
     * A grant to an identity that is no principal reaches the grant hook as a
     * grant to the identity itself and is written; the identity is then allowed
     * what it was granted, and nothing else, through the manager and the Gate
     * alike.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAGrantToAnIdentityThatIsNoPrincipalIsWrittenAndDecided(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $hook  = new RecordingGrantHook;
        $staff = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);

        $this->app?->instance(GrantHook::class, $hook);

        self::assertFalse(Authorization::forUser($staff)->can(InvoicePermission::REFUND->value));

        $staff->givePermission(InvoicePermission::REFUND->value);

        self::assertCount(1, $hook->widenings);
        self::assertEquals(Reference::of($staff), $hook->widenings[0]->identity);
        self::assertTrue($hook->widenings[0]->isToIdentity());
        self::assertTrue($staff->hasPermission(InvoicePermission::REFUND->value));

        self::assertTrue(Authorization::forUser($staff)->can(InvoicePermission::REFUND->value));
        self::assertTrue(Gate::forUser($staff)->allows(InvoicePermission::REFUND->value));
        self::assertFalse(Authorization::forUser($staff)->can(InvoicePermission::VOID->value));
    }

    /**
     * Declare the invoice permissions, set before any provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $app->make('config')->set('authorization.permission_enums', [InvoicePermission::class]);
    }
}
