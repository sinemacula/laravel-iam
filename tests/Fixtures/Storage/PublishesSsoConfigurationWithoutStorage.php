<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Storage;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Arr;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Stands in for an application's published `config/sso.php` from a version of
 * the member without its `storage` block: registered before every package
 * provider, it puts that configuration in place as Laravel loads an
 * application's configuration files, before any provider registers.
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
