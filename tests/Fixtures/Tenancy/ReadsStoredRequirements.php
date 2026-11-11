<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * MFA's tenant requirement kept in the application's own table, read on the
 * default connection every time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReadsStoredRequirements implements TenantRequirement
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
     * Multifactor authentication where the tenant's row requires it, otherwise
     * nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, string $tenant): Requirement
    {
        $stored = DB::table(self::TABLE)->where('tenant_id', $tenant)->first();

        return $stored !== null && (bool) $stored->multifactor ? Requirement::none()->withMultifactor() : Requirement::none();
    }
}
