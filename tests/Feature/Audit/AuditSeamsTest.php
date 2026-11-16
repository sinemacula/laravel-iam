<?php

declare(strict_types = 1);

namespace Tests\Feature\Audit;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\HeldActorReader;
use SineMacula\Laravel\Iam\Audit\AuditSeams;
use SineMacula\Laravel\Iam\Audit\AuthenticationActorReader;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\IamServiceProvider;
use Tests\Fixtures\Providers\ExtendsTheHeldActorReader;
use Tests\TestCase;

/**
 * Feature tests for the seam audit-log reads the caller a guard holds through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditSeams::class)]
final class AuditSeamsTest extends TestCase
{
    /**
     * The reader is the one binding, shared, on and not mandatory.
     *
     * @return void
     */
    public function testTheReaderIsTheOneSharedOptionalBinding(): void
    {
        $bindings = (new AuditSeams)->seams(new Repository);

        self::assertCount(1, $bindings);
        self::assertSame(HeldActorReader::class, $bindings[0]->abstract);
        self::assertSame(AuthenticationActorReader::class, $bindings[0]->adapter);
        self::assertSame(Lifetime::SHARED, $bindings[0]->lifetime);
        self::assertTrue($bindings[0]->on);
        self::assertFalse($bindings[0]->isMandatory());
    }

    /**
     * Audit-log is given one shared reader.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheReaderIsOneSharedInstance(): void
    {
        $reader = $this->app?->make(HeldActorReader::class);

        self::assertInstanceOf(AuthenticationActorReader::class, $reader);
        self::assertSame($reader, $this->app?->make(HeldActorReader::class));
    }

    /**
     * Rows of `[providers]`: the application's extending provider registered
     * before and after this package's.
     *
     * @return iterable<string, array{0: list<class-string<\Illuminate\Support\ServiceProvider>>}>
     */
    public static function provideExtensionOrders(): iterable
    {
        yield 'extended before this package registers' => [[ExtendsTheHeldActorReader::class, ...self::MEMBER_PROVIDERS, IamServiceProvider::class]];

        yield 'extended after this package registers' => [[...self::MEMBER_PROVIDERS, IamServiceProvider::class, ExtendsTheHeldActorReader::class]];
    }

    /**
     * An extension made in any `register()` is handed the package's reader.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideExtensionOrders')]
    public function testAnExtensionIsHandedThePackagesReader(array $providers): void
    {
        $this->reorderProviders($providers);

        $this->app?->make(HeldActorReader::class);

        self::assertSame(AuthenticationActorReader::class, $this->app?->make(ExtendsTheHeldActorReader::RECORDED));
    }
}
