<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRule;

/**
 * A tenant MFA requirement the application keeps in its own table, read on the
 * default connection every time it is asked, as an application's own data is: a
 * tenant whose row requires multifactor requires a further factor at the row's
 * version, and a tenant with no row requires nothing at a version of its own.
 * So a transaction that changed a row answers the change, and another
 * transaction answers what it reads committed, or what its snapshot holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReadsStoredRequirements implements TenantMfaRequirement
{
    /** @var string The table the requirements are kept in. */
    public const string TABLE = 'iam_stored_tenant_requirements';

    /**
     * Create the table on the connection.
     *
     * @param  string  $connection
     * @return void
     */
    public static function createTable(string $connection): void
    {
        Schema::connection($connection)->create(self::TABLE, static function (Blueprint $table): void {
            $table->string('tenant_id')->primary();
            $table->boolean('multifactor');
            $table->unsignedInteger('version');
        });
    }

    /**
     * Drop the table from the connection.
     *
     * @param  string  $connection
     * @return void
     */
    public static function dropTable(string $connection): void
    {
        Schema::connection($connection)->dropIfExists(self::TABLE);
    }

    /**
     * What the tenant's row requires, read on the default connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $application
     * @return \SineMacula\Laravel\Iam\Tenancy\TenantMfaRule
     */
    #[\Override]
    public function requirementFor(Tenant $tenant, string $application): TenantMfaRule
    {
        $stored = DB::table(self::TABLE)->where('tenant_id', IdentifierCoercion::stringify($tenant->getTenantIdentifier()))->first();

        if ($stored === null) {
            return new TenantMfaRule(new Requirement, 'stored-none');
        }

        $requirement = (bool) $stored->multifactor ? new Requirement(multifactor: new RequirementPart) : new Requirement;

        return new TenantMfaRule($requirement, 'stored-' . (int) $stored->version);
    }
}
