<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Create the machines table the test machine identities live in, on the default
 * connection, which the tests keep as the shared storage connection with every
 * member's tables.
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
        Schema::create('iam_machines', static function (Blueprint $table): void {

            $table->id();
            $table->string('name');
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
        Schema::dropIfExists('iam_machines');
    }
};
