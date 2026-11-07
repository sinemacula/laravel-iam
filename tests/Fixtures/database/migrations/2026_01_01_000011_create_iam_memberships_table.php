<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Tests\Fixtures\Models\Person;

/**
 * Create the table the tests' application keeps each person's memberships in, a
 * tenant's or a platform principal (no tenant), with when the person accepted
 * each, on the default connection, which the tests keep as the shared storage
 * connection with every member's tables.
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
        Schema::create('iam_memberships', static function (Blueprint $table): void {

            $table->id();
            $table->foreignIdFor(Person::class)->index();
            $table->string('tenant_id')->nullable();
            $table->timestamp('accepted_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migration.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::dropIfExists('iam_memberships');
    }
};
