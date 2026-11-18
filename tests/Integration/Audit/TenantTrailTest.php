<?php

declare(strict_types = 1);

namespace Tests\Integration\Audit;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Iam\Authorization\AuditAccessPolicyAdapter;
use SineMacula\Laravel\Iam\Authorization\PermissionCatalogue;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Concerns\MigratesAuditLog;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Authorization\Staff;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration test for the members' records of a session acting in a tenant,
 * read by that tenant's viewers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(References::class)]
#[CoversClass(AuditAccessPolicyAdapter::class)]
final class TenantTrailTest extends TestCase
{
    use ArrangesFactorChanges, MigratesAuditLog, SignsInPeople;

    /**
     * Store the catalogue's permissions and resolve the organisations.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        foreach ((new PermissionCatalogue)->permissions() as $definition) {
            Permission::query()->create(['name' => $definition->name]);
        }

        $this->app?->singleton(TenantResolver::class, OrganisationTenancy::class);
        $this->app?->singleton(TenantAccess::class, OrganisationTenancy::class);
    }

    /**
     * Each tenant's viewer reads its own tenant's step-ups and none of the
     * other's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachTenantsViewerReadsOnlyItsOwnStepUps(): void
    {
        $ada   = $this->steppedUpIn('org-1', 'ada@example.test');
        $grace = $this->steppedUpIn('org-2', 'grace@example.test');

        foreach ([[$ada, 'org-1', 'alan@example.test'], [$grace, 'org-2', 'edsger@example.test']] as [$person, $tenant, $viewer]) {
            self::assertEqualsCanonicalizing([
                ['mfa.verification_passed', Person::class, $person, References::TENANT_TYPE, $tenant],
                ['session.stepped_up', Person::class, $person, References::TENANT_TYPE, $tenant],
            ], self::stepUpsVisibleTo($this->viewerIn($tenant, $viewer)));
        }
    }

    /**
     * Run every member's migrations, `laravel-authorization`'s among them.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(dirname(__DIR__, 2) . '/Fixtures/database/migrations');

        $providers = [
            AuthenticationServiceProvider::class,
            MfaServiceProvider::class,
            SsoServiceProvider::class,
            AuditLogServiceProvider::class,
            AuthorizationServiceProvider::class,
        ];

        foreach ($providers as $provider) {

            $file = (new \ReflectionClass($provider))->getFileName();

            assert(is_string($file));

            $this->loadMigrationsFrom(dirname($file, 2) . '/database/migrations');
        }
    }

    /**
     * Name the catalogue before any provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $app->make('config')->set('authorization.permission_providers', [PermissionCatalogue::class]);
    }

    /**
     * Sign a person in to the tenant, step the session up with a factor and
     * return the person's key.
     *
     * @param  string  $tenant
     * @param  string  $email
     * @return string
     *
     * @throws \Throwable
     */
    private function steppedUpIn(string $tenant, string $email): string
    {
        $person  = $this->createPerson($email);
        $session = $this->signIn($person)->record;

        $session->forceFill([$session->getTenantIdName() => $tenant])->save();

        $this->actingOnSession($session, self::GUARD);

        $factor = $this->confirmedFactor($person);

        self::assertTrue(Mfa::verify(self::callerOf($person), Submission::factor($factor->id, AuthenticatorApp::code($factor)), Purpose::STEP_UP)->isVerified());

        $this->stopActing(self::GUARD);

        return (string) $person->id;
    }

    /**
     * A viewer granted `audit-log.read` in the tenant.
     *
     * @param  string  $tenant
     * @param  string  $email
     * @return \Tests\Fixtures\Authorization\Staff
     */
    private function viewerIn(string $tenant, string $email): Staff
    {
        $viewer = Staff::query()->create(['name' => 'Viewer', 'email' => $email]);

        $viewer->givePermission('audit-log.read', tenant: new Reference(Organisation::TYPE, $tenant));

        return $viewer;
    }

    /**
     * The code, actor and tenant of each step-up record the viewer reads.
     *
     * @param  \Tests\Fixtures\Authorization\Staff  $viewer
     * @return list<list<?string>>
     *
     * @throws \Throwable
     */
    private static function stepUpsVisibleTo(Staff $viewer): array
    {
        $page = AuditLog::trail()->forEvent('session.stepped_up', 'mfa.verification_passed')->visibleTo($viewer)->cursorPaginate(10);

        return array_map(static fn (TrailEntry $entry): array => [
            $entry->event,
            $entry->actor?->type,
            $entry->actor?->id,
            $entry->tenant?->type,
            $entry->tenant?->id,
        ], $page->entries);
    }
}
