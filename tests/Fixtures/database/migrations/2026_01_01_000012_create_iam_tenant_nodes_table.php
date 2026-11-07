<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Create the table the tests' application keeps its tenant tree in, each tenant
 * with its parent's id (none for a root), on the default connection, which the
 * tests keep as the shared storage connection with every member's tables.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */

return new class extends Migration {
    /**
     * Run the migration.
     *
     * @return void
     */
    public function up(): void
    {
        Schema::create('iam_tenant_nodes', static function (Blueprint $table): void {

            $table->string('tenant_id')->primary();
            $table->string('parent_id')->nullable()->index();
        });
    }

    /**
     * Reverse the migration.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::dropIfExists('iam_tenant_nodes');
    }
};
