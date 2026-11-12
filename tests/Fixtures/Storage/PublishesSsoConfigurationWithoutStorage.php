<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Storage;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Arr;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Stands in for a published `config/sso.php` without its `storage` block.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PublishesSsoConfigurationWithoutStorage extends ServiceProvider
{
    /**
     * Put the published configuration in place.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function register(): void
    {
        $file = dirname((string) (new \ReflectionClass(SsoServiceProvider::class))->getFileName()) . '/../config/sso.php';

        /** @var array<string, mixed> $packaged */
        $packaged = require $file;

        $this->app->make(Repository::class)->set('sso', Arr::except($packaged, 'storage'));
    }
}
