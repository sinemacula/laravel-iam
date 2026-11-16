<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\AuditLog\Contracts\HeldActorReader;

/**
 * An application's own provider that extends audit-log's held actor reader from
 * its `register()`, recording the class of the reader it was handed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExtendsTheHeldActorReader extends ServiceProvider
{
    /** @var string The container key the record is kept under. */
    public const string RECORDED = 'tests.providers.extended-held-actor-reader';

    /**
     * Extend the reader, recording the class of the one it wraps.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->extend(HeldActorReader::class, static function (HeldActorReader $reader, Application $app): HeldActorReader {
            $app->instance(self::RECORDED, $reader::class);

            return $reader;
        });
    }
}
