<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Tests\Fixtures\Models\Person;

/**
 * Create the table the fixture provisioner writes each provisioned person's
 * membership of a tenant to, on the default connection, which the tests keep as
 * the shared storage connection with every member's tables.
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
        Schema::create('iam_provisioned_memberships', static function (Blueprint $table): void {

            $table->id();
            $table->foreignIdFor(Person::class);
            $table->string('tenant_id');
            $table->timestamps();

            $table->unique(['person_id', 'tenant_id']);
        });
    }

    /**
     * Reverse the migration.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::dropIfExists('iam_provisioned_memberships');
    }
};
